// Ports dnsdata-go `cmd/dnsview/run_test.go`: the signed vectors in
// tests/testdata/signed (shared byte for byte with dnsdata-go) served
// from the in-memory authority, one JSON line per query.

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { parseRootAnchors } from '../../src/dnssec/root_anchors';
import { Authority, new_authority, with_zone } from '../../src/resolver/memory';
import { ResolverResponse } from '../../src/resolver/response';
import { RRTypeName } from '../../src/types/dns_type_table';
import { Resolver, Result, Verdict, Verifier } from '../../src/verifier';
import {
    Config, EXIT_OK, EXIT_QUERY_ERROR, EXIT_USAGE, Env, parse_duration_ms, run,
} from '../../src/cli/dnsview';
import { readZone } from '../resolver/memory/helpers';

const signedDir = path.join(__dirname, '..', 'testdata', 'signed');
const anchorsFile = path.join(signedDir, 'root-anchors.json');
const vectorClock = new Date('2026-06-01T00:00:00Z');

interface VectorCase {
    qname: string;
    qtype: number;
    clock: string;
    verdict: string;
}

interface Line {
    query: { name: string; type: string };
    server: string;
    error?: string;
    result: Result | null;
}

interface Outcome {
    code: number;
    stdout: string;
    stderr: string;
}

function read(name: string): string {
    return fs.readFileSync(path.join(signedDir, name), 'utf8');
}

function loadAuthority(): Authority {
    return new_authority(
        with_zone('.', readZone(read('root.zone'))),
        with_zone('test.', readZone(read('test.zone'))),
        with_zone('example.test.', readZone(read('example.test.zone'))),
    );
}

const cases = (JSON.parse(read('cases.json')) as { cases: VectorCase[] }).cases;

async function runWith(resolver: Resolver | null, now: Date, ...argv: string[]): Promise<Outcome> {
    let stdout = '';
    let stderr = '';
    const env: Env = {
        stdout: (t) => { stdout += t; },
        stderr: (t) => { stderr += t; },
        now: () => now,
        new_resolver: () => {
            if (resolver === null) throw new Error('no resolver in this test');
            return resolver;
        },
    };
    const code = await run(argv, env);
    return { code, stdout, stderr };
}

function lines(stdout: string): Line[] {
    return stdout.trimEnd().split('\n').map((s) => JSON.parse(s) as Line);
}

function failing(message: string): Resolver {
    return { query: async (): Promise<ResolverResponse> => { throw new Error(message); } };
}

// The fields each verdict is defined to carry.
function expectVerdictFields(r: Result): void {
    switch (r.verdict) {
    case Verdict.Secure:
        expect(r.answer?.records.length).toBeGreaterThan(0);
        break;
    case Verdict.SecureNoData:
    case Verdict.SecureNXDomain:
        expect(r.negativeReason).toBeTruthy();
        expect(r.answer).toBeUndefined();
        break;
    case Verdict.Insecure:
        expect(r.insecureAt).toBeTruthy();
        expect(r.answer).toBeUndefined();
        break;
    case Verdict.Bogus:
        expect(r.bogusAt).toBeTruthy();
        expect(r.bogusReason).toBeTruthy();
        expect(r.answer).toBeUndefined();
        break;
    }
    // A bogus root DNSKEY rrset (signature out of its window) fails
    // before the first step is recorded.
    if (r.verdict !== Verdict.Bogus) expect(r.chain.length).toBeGreaterThan(0);
}

describe('dnsview on the shared signed vectors', () => {
    const auth = loadAuthority();

    it.each(cases.map((c) => [`${c.qname}/${c.qtype}@${c.clock}`, c] as const))('%s', async (_name, c) => {
        // Lower case on purpose: types are matched in any case.
        const type = RRTypeName(c.qtype).toLowerCase();
        const out = await runWith(auth, new Date(c.clock),
            '-server', '192.0.2.53', '-anchors', anchorsFile, '-type', type, c.qname);
        expect(out.code).toBe(EXIT_OK);
        const ls = lines(out.stdout);
        expect(ls).toHaveLength(1);
        const [l] = ls;
        expect(l.query).toEqual({ name: c.qname, type: RRTypeName(c.qtype) });
        expect(l.server).toBe('192.0.2.53:53');
        expect(l.error).toBeUndefined();
        expect(l.result).not.toBeNull();
        const r = l.result as Result;
        expect(`${r.verdict} (${r.bogusReason ?? ''})`).toBe(
            `${c.verdict} (${c.verdict === Verdict.Bogus ? r.bogusReason ?? '' : ''})`);
        expectVerdictFields(r);
    });
});

describe('dnsview output', () => {
    const auth = loadAuthority();

    it('carries the verifier Result as is under "result"', async () => {
        const out = await runWith(auth, vectorClock, '-server', '192.0.2.53', '-anchors', anchorsFile, 'www.example.test.');
        const v = new Verifier({ resolver: auth, trustAnchors: parseRootAnchors(read('root-anchors.json')), now: () => vectorClock });
        const want = await v.validate('www.example.test.', 1);
        const top = JSON.parse(out.stdout) as Record<string, unknown>;
        expect(Object.keys(top)).toEqual(['query', 'server', 'result']);
        expect(JSON.stringify(top.result)).toBe(JSON.stringify(want));
    });

    it('writes one line per name and type, in order', async () => {
        const out = await runWith(auth, vectorClock, '-server=192.0.2.53:5353', '--anchors', anchorsFile,
            '-type', 'A, mx', 'www.example.test.', 'nope.example.test.');
        expect(out.code).toBe(EXIT_OK);
        expect(lines(out.stdout).map((l) => [l.query.name, l.query.type, l.server, l.result?.verdict])).toEqual([
            ['www.example.test.', 'A', '192.0.2.53:5353', 'secure'],
            ['www.example.test.', 'MX', '192.0.2.53:5353', 'secure-nodata'],
            ['nope.example.test.', 'A', '192.0.2.53:5353', 'secure-nxdomain'],
            ['nope.example.test.', 'MX', '192.0.2.53:5353', 'secure-nxdomain'],
        ]);
    });

    it('uses the built-in IANA anchors without -anchors', async () => {
        const out = await runWith(auth, vectorClock, '-server', '192.0.2.53', 'www.example.test.');
        expect(lines(out.stdout)[0].result?.verdict).not.toBe(Verdict.Secure);
    });

    it('reports a resolver failure on its line, with result null, and exits 1', async () => {
        const out = await runWith(failing('unreachable'), vectorClock, '-server', '192.0.2.53', 'a.test.', 'b.test.');
        expect(out.code).toBe(EXIT_QUERY_ERROR);
        const ls = lines(out.stdout);
        expect(ls).toHaveLength(2);
        for (const l of ls) {
            expect(l.error).toContain('unreachable');
            expect(l.result).toBeNull();
        }
    });

    it('aborts a query at -timeout', async () => {
        const hanging: Resolver = {
            query: (_name, _qtype, signal) => new Promise<ResolverResponse>((_resolve, reject) => {
                signal?.addEventListener('abort', () => reject(new Error('aborted')));
            }),
        };
        const out = await runWith(hanging, vectorClock, '-server', '192.0.2.53', '-timeout', '20ms', 'a.test.');
        expect(out.code).toBe(EXIT_QUERY_ERROR);
        expect(lines(out.stdout)[0].error).toBeTruthy();
    });

    it('passes the configuration to the resolver', async () => {
        let got: Config | undefined;
        await run(['-server', '2001:db8::53', '-cd', '-timeout', '3s', 'x.test.'], {
            stdout: () => undefined,
            stderr: () => undefined,
            now: () => new Date(),
            new_resolver: (cfg) => { got = cfg; return failing('offline'); },
        });
        expect(got?.server).toBe('[2001:db8::53]:53');
        expect(got?.cd).toBe(true);
        expect(got?.timeout_ms).toBe(3000);
        expect(got?.queries.map((q) => q.type)).toEqual(['A']);
    });
});

// NAME goes to validate() as typed. The verifier lower-cases it and adds
// the trailing dot, so any spelling gives the verdict and the result of
// the canonical name; query.name echoes the spelling given.
describe('dnsview name spellings', () => {
    const auth = loadAuthority();

    async function resultOf(name: string, type: string): Promise<Record<string, unknown>> {
        const out = await runWith(auth, vectorClock, '-server', '192.0.2.53', '-anchors', anchorsFile, '-type', type, name);
        expect(out.code).toBe(EXIT_OK);
        return JSON.parse(out.stdout) as Record<string, unknown>;
    }

    const groups: ReadonlyArray<[string, string, string, string[]]> = [
        ['test.', 'SOA', 'secure', ['test', 'Test.', 'TEST']],
        ['www.example.test.', 'A', 'secure', ['www.example.test', 'WWW.Example.TEST.', 'Www.Example.Test']],
        ['example.test.', 'SOA', 'secure', ['example.test', 'Example.Test.', 'EXAMPLE.TEST']],
        ['nope.example.test.', 'A', 'secure-nxdomain', ['nope.example.test', 'NOPE.example.test.']],
        ['www.example.test.', 'MX', 'secure-nodata', ['WWW.EXAMPLE.TEST']],
        ['x.wild.example.test.', 'A', 'secure', ['X.Wild.Example.Test']],
        ['alias.example.test.', 'A', 'secure', ['Alias.Example.Test']],
        ['www.insecure.test.', 'A', 'insecure', ['WWW.Insecure.Test']],
    ];
    const rows = groups.flatMap(([canonical, type, verdict, spellings]) =>
        spellings.map((s) => [`${s}/${type}`, s, canonical, type, verdict] as const));

    it.each(rows)('%s', async (_name, spelling, canonical, type, verdict) => {
        const want = await resultOf(canonical, type);
        const got = await resultOf(spelling, type);
        expect((got.result as Result).verdict).toBe(verdict);
        expect((got.query as { name: string }).name).toBe(spelling);
        expect(JSON.stringify(got.result)).toBe(JSON.stringify(want.result));
    });
});

describe('dnsview usage', () => {
    const missing = path.join(os.tmpdir(), 'dnsview-no-such-anchors.json');

    it.each([
        ['no server', ['x.test.']],
        ['no name', ['-server', '192.0.2.53']],
        ['unknown type', ['-server', '192.0.2.53', '-type', 'NOSUCHTYPE', 'x.test.']],
        ['zero timeout', ['-server', '192.0.2.53', '-timeout', '0s', 'x.test.']],
        ['malformed timeout', ['-server', '192.0.2.53', '-timeout', '10', 'x.test.']],
        ['missing anchors', ['-server', '192.0.2.53', '-anchors', missing, 'x.test.']],
        ['bad anchors', ['-server', '192.0.2.53', '-anchors', path.join(signedDir, 'root.zone'), 'x.test.']],
        ['unknown flag', ['-bogus']],
        ['flag without value', ['-server']],
        ['bad boolean', ['-cd=maybe', '-server', '192.0.2.53', 'x.test.']],
    ])('%s', async (_name, argv) => {
        const out = await runWith(null, vectorClock, ...argv);
        expect(out.code).toBe(EXIT_USAGE);
        expect(out.stdout).toBe('');
        expect(out.stderr).toContain('usage: dnsview');
    });

    it('prints usage on -h and exits 0', async () => {
        const out = await runWith(null, vectorClock, '-h');
        expect(out.code).toBe(EXIT_OK);
        expect(out.stdout).toBe('');
        expect(out.stderr).toContain('-server');
    });

    it.each([
        ['10s', 10_000], ['500ms', 500], ['1m30s', 90_000], ['1.5s', 1500], ['2h', 7_200_000], ['0', 0],
        ['10', null], ['', null], ['s', null], ['-1s', null],
    ] as const)('parse_duration_ms(%j) = %j', (input, want) => {
        expect(parse_duration_ms(input)).toBe(want);
    });
});
