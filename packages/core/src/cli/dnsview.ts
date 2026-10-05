#!/usr/bin/env node
// dnsview: validate DNS queries against one server with the chain
// Verifier and print each Result as one line of JSON. A diagnostic
// tool: it shows, query by query, what the verifier concluded and why.
//
//   dnsview -server ADDR [-type A,AAAA] [-anchors FILE] [-cd] [-timeout 10s] NAME...
//
// Each NAME is queried for each -type, in order, and produces one line:
//
//   {"query":{"name":"…","type":"A"},"server":"…","error":"…","result":{…}}
//
// "error" is present only when validation threw; "result" is the
// verifier's Result as JSON.stringify renders it, or null when
// validate() threw. Queries go to the server over UDP, retried over TCP
// when the answer is truncated. Without -anchors the built-in IANA root
// anchors are used. Exit status: 0 when every query produced a result,
// 1 when at least one did not, 2 on a usage error.
//
// Ports dnsdata-go `cmd/dnsview` (UP-020). Flags are parsed the way Go's
// `flag` package does: `-name value`, `-name=value` or `--name`, and
// parsing stops at the first argument that is not a flag. The JSON is
// compared with the Go command by meaning, not byte for byte (empty
// chain / evidence, timestamp precision and key order may differ).

import * as fs from 'fs';
import { registerAllHandlers } from '../index';
import { RRTypeName, StringToRRType } from '../types/dns_type_table';
import { BUILTIN_ROOT_ANCHORS, RootAnchors, parseRootAnchors } from '../dnssec/root_anchors';
import { AuthClient, normalize_addr } from '../resolver/auth';
import { Resolver, Result, Verifier } from '../verifier';
import { error_message } from '../verifier/verifier';

export const DEFAULT_TIMEOUT_MS = 10_000;

export const EXIT_OK = 0;
export const EXIT_QUERY_ERROR = 1;
export const EXIT_USAGE = 2;

export const USAGE = `usage: dnsview -server ADDR [-type A,AAAA] [-anchors FILE] [-cd] [-timeout 10s] NAME...
  -server ADDR    server to query, ip or ip:port (required)
  -type LIST      comma-separated RR types; mnemonics or TYPE<n>, any case (default A)
  -anchors FILE   root trust anchors JSON (default: built-in IANA root anchors)
  -cd             set the CD (checking disabled) bit on queries
  -timeout DUR    time limit for each query's validation, e.g. 10s, 500ms (default 10s)`;

export interface Query {
    name: string;
    type: string;
    qtype: number;
}

export interface Config {
    server: string;        // normalised ip:port
    anchors: RootAnchors;
    cd: boolean;
    timeout_ms: number;
    queries: Query[];
}

// What run() needs from the outside, so tests can swap the transport
// and the clock.
export interface Env {
    stdout(text: string): void;
    stderr(text: string): void;
    now(): Date;
    new_resolver(cfg: Config): Resolver;
}

export interface OutputLine {
    query: { name: string; type: string };
    server: string;
    error?: string;
    result: Result | null;
}

export type ParseOutcome =
    | { kind: 'config'; config: Config }
    | { kind: 'help' }
    | { kind: 'error'; message: string };

const VALUE_FLAGS = new Set(['server', 'anchors', 'type', 'timeout']);
const BOOL_FLAGS = new Set(['cd']);

const DURATION_UNITS_MS: Record<string, number> = { ms: 1, s: 1000, m: 60_000, h: 3_600_000 };

// Queries cfg.server directly: UDP, then TCP on truncation.
export function auth_resolver(cfg: Config): Resolver {
    const client = new AuthClient({
        servers: [cfg.server],
        timeout_ms: cfg.timeout_ms,
        checking_disabled: cfg.cd,
    });
    return { query: client.resolve.bind(client) };
}

export async function run(argv: readonly string[], env: Env): Promise<number> {
    // Handler registration is opt-in; the DNSKEY / DS / RRSIG / NSEC
    // records do not decode without it.
    registerAllHandlers();
    const parsed = parse_args(argv);
    if (parsed.kind === 'help') {
        env.stderr(`${USAGE}\n`);
        return EXIT_OK;
    }
    if (parsed.kind === 'error') {
        env.stderr(`dnsview: ${parsed.message}\n${USAGE}\n`);
        return EXIT_USAGE;
    }
    const cfg = parsed.config;
    const verifier = new Verifier({ resolver: env.new_resolver(cfg), trustAnchors: cfg.anchors, now: env.now });
    let status = EXIT_OK;
    for (const q of cfg.queries) {
        const line = await validate_one(verifier, cfg, q);
        if (line.error !== undefined) status = EXIT_QUERY_ERROR;
        env.stdout(`${JSON.stringify(line)}\n`);
    }
    return status;
}

async function validate_one(v: Verifier, cfg: Config, q: Query): Promise<OutputLine> {
    const query = { name: q.name, type: q.type };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), cfg.timeout_ms);
    try {
        const result = await v.validate(q.name, q.qtype, controller.signal);
        return { query, server: cfg.server, result };
    } catch (err) {
        return { query, server: cfg.server, error: error_message(err), result: null };
    } finally {
        clearTimeout(timer);
    }
}

export function parse_args(argv: readonly string[]): ParseOutcome {
    const values: Record<string, string> = { type: 'A', timeout: '10s' };
    let cd = false;
    let i = 0;
    for (; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === '--') { i++; break; }
        if (!arg.startsWith('-') || arg === '-') break;
        const body = arg.replace(/^--?/, '');
        const eq = body.indexOf('=');
        const name = eq < 0 ? body : body.slice(0, eq);
        if (name === 'h' || name === 'help') return { kind: 'help' };
        if (BOOL_FLAGS.has(name)) {
            const v = eq < 0 ? 'true' : body.slice(eq + 1);
            if (v !== 'true' && v !== 'false') return { kind: 'error', message: `invalid boolean value "${v}" for -${name}` };
            cd = v === 'true';
        } else if (VALUE_FLAGS.has(name)) {
            if (eq >= 0) {
                values[name] = body.slice(eq + 1);
            } else if (i + 1 < argv.length) {
                values[name] = argv[++i];
            } else {
                return { kind: 'error', message: `flag needs an argument: -${name}` };
            }
        } else {
            return { kind: 'error', message: `flag provided but not defined: -${name}` };
        }
    }
    return build_config(values, cd, argv.slice(i));
}

function build_config(values: Record<string, string>, cd: boolean, names: readonly string[]): ParseOutcome {
    const fail = (message: string): ParseOutcome => ({ kind: 'error', message });
    if (!values.server) return fail('-server is required');
    if (names.length === 0) return fail('at least one NAME is required');
    const timeout_ms = parse_duration_ms(values.timeout);
    if (timeout_ms === null) return fail(`invalid value "${values.timeout}" for -timeout`);
    if (timeout_ms <= 0) return fail(`-timeout must be positive, got ${values.timeout}`);
    const qtypes: number[] = [];
    for (const s of values.type.split(',')) {
        try {
            qtypes.push(StringToRRType(s.trim().toUpperCase()));
        } catch (err) {
            return fail(`-type "${s}": ${error_message(err)}`);
        }
    }
    let anchors: RootAnchors;
    try {
        anchors = load_anchors(values.anchors);
    } catch (err) {
        return fail(`-anchors ${values.anchors}: ${error_message(err)}`);
    }
    return {
        kind: 'config',
        config: {
            server: normalize_addr(values.server),
            anchors,
            cd,
            timeout_ms,
            queries: cross_queries(names, qtypes),
        },
    };
}

// Go-style durations: one or more <number><unit> with unit ms, s, m or
// h ("10s", "1m30s", "1.5s"). A bare "0" is zero. null when malformed.
export function parse_duration_ms(s: string): number | null {
    if (s === '0') return 0;
    if (!/^(\d+(\.\d+)?(ms|s|m|h))+$/.test(s)) return null;
    const part = /(\d+(?:\.\d+)?)(ms|s|m|h)/g;
    let total = 0;
    for (let m = part.exec(s); m !== null; m = part.exec(s)) {
        total += Number(m[1]) * DURATION_UNITS_MS[m[2]];
    }
    return total;
}

function cross_queries(names: readonly string[], qtypes: readonly number[]): Query[] {
    const out: Query[] = [];
    for (const name of names) {
        for (const qtype of qtypes) out.push({ name, type: RRTypeName(qtype), qtype });
    }
    return out;
}

function load_anchors(file: string | undefined): RootAnchors {
    if (!file) return BUILTIN_ROOT_ANCHORS;
    return parseRootAnchors(fs.readFileSync(file, 'utf8'));
}

if (require.main === module) {
    run(process.argv.slice(2), {
        stdout: (text) => process.stdout.write(text),
        stderr: (text) => process.stderr.write(text),
        now: () => new Date(),
        new_resolver: auth_resolver,
    }).then((code) => {
        process.exitCode = code;
    }, (err: unknown) => {
        process.stderr.write(`dnsview: ${error_message(err)}\n`);
        process.exitCode = EXIT_QUERY_ERROR;
    });
}
