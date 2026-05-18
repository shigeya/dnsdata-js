// dnsdata CLI entry point.
//
// Resolves a single (qname, qtype) lookup via either RFC 8484 DoH
// (lib/resolver/doh) or RFC 1035 plain UDP/TCP DNS
// (lib/resolver_auth), then runs the chain Verifier
// (lib/verifier) for DNSSEC validation. Output is dig-like and
// reflects the verifier's six-state verdict.
//
// P2 of REFACTOR_PLAN.md deleted the legacy cli/resolver*, cli/
// dnssec_verifier, and cli/error_util shims; everything below routes
// through the same lib/ surface that mailsec-probe and other
// downstream consumers use.

import { StringToRRType } from '../types/dns_type_table';
import {
    DoHClient,
    DEFAULT_GOOGLE,
    DEFAULT_CLOUDFLARE,
    DEFAULT_QUAD9,
    default_providers,
} from '../lib/resolver/doh';
import { AuthClient } from '../lib/resolver_auth';
import { Verifier, Resolver, Result } from '../lib/verifier';
import { ResourceRecord } from '../lib/dns_zone';
import { format_output } from './output';
import { fetch_and_update_root_anchors } from './root_anchor_updater';

type Method = 'doh' | 'auth';

interface CLIOptions {
    method: Method;
    doh_providers: string[];   // URLs or shorthand names; empty -> DoHClient defaults
    auth_servers: string[];    // host[:port]; empty -> DEFAULT_AUTH_SERVERS
    dnssec: boolean;
    update_root_anchors: boolean;
    fqdn: string;
    rrtype: string;
}

const DOH_SHORTHANDS: Record<string, string> = {
    google: DEFAULT_GOOGLE,
    cloudflare: DEFAULT_CLOUDFLARE,
    cf: DEFAULT_CLOUDFLARE,
    quad9: DEFAULT_QUAD9,
};

// Default authoritative resolver list when the user doesn't pass
// --auth-server. These are public open resolvers; production callers
// should always override.
const DEFAULT_AUTH_SERVERS = ['8.8.8.8:53', '1.1.1.1:53', '9.9.9.9:53'];

function resolve_doh_url(s: string): string {
    return DOH_SHORTHANDS[s.toLowerCase()] ?? s;
}

function err_message(err: unknown): string {
    if (err instanceof Error) return err.message;
    return String(err);
}

function print_usage(): void {
    console.log(`Usage: dnsdata [options] <fqdn> <rrtype>
       dnsdata --update-root-anchors [--doh-provider <url|name>]...

Options:
  --method doh|auth          Resolver method (default: doh)
  --doh-provider <url|name>  DoH endpoint URL or shorthand: google,
                             cloudflare (cf), quad9. Repeat for failover.
                             Defaults to all three.
  --auth-server <host[:port]>
                             Authoritative server for --method auth.
                             Repeat for failover. Defaults to
                             ${DEFAULT_AUTH_SERVERS.join(', ')}.
  --no-dnssec                Skip DNSSEC chain verification
  --update-root-anchors      Fetch IANA root trust anchors and save
                             to ~/.dnsdata/root-anchors.json
  --help, -h                 Show this help

Examples:
  dnsdata example.com A
  dnsdata --doh-provider cloudflare example.com AAAA
  dnsdata --method auth --auth-server 1.1.1.1 example.com MX
  dnsdata --no-dnssec example.com TXT
  dnsdata --update-root-anchors`);
}

function parse_args(argv: string[]): CLIOptions {
    const args = argv.slice(2);
    const opts: CLIOptions = {
        method: 'doh',
        doh_providers: [],
        auth_servers: [],
        dnssec: true,
        update_root_anchors: false,
        fqdn: '',
        rrtype: '',
    };

    const positional: string[] = [];
    let i = 0;
    while (i < args.length) {
        const arg = args[i];
        if (arg === '--help' || arg === '-h') {
            print_usage();
            process.exit(0);
        } else if (arg === '--method') {
            i++;
            const val = args[i];
            if (val !== 'doh' && val !== 'auth') {
                console.error(`Error: --method must be 'doh' or 'auth', got '${val}'`);
                process.exit(1);
            }
            opts.method = val;
        } else if (arg === '--doh-provider') {
            i++;
            const val = args[i];
            if (!val) {
                console.error('Error: --doh-provider requires a value');
                process.exit(1);
            }
            opts.doh_providers.push(resolve_doh_url(val));
        } else if (arg === '--auth-server') {
            i++;
            const val = args[i];
            if (!val) {
                console.error('Error: --auth-server requires a value');
                process.exit(1);
            }
            opts.auth_servers.push(val);
        } else if (arg === '--no-dnssec') {
            opts.dnssec = false;
        } else if (arg === '--update-root-anchors') {
            opts.update_root_anchors = true;
        } else if (arg.startsWith('-')) {
            console.error(`Error: Unknown option '${arg}'`);
            print_usage();
            process.exit(1);
        } else {
            positional.push(arg);
        }
        i++;
    }

    if (opts.update_root_anchors) {
        return opts;
    }

    if (positional.length < 2) {
        console.error('Error: <fqdn> and <rrtype> are required');
        print_usage();
        process.exit(1);
    }

    opts.fqdn = positional[0];
    opts.rrtype = positional[1].toUpperCase();

    try {
        StringToRRType(opts.rrtype);
    } catch {
        console.error(`Error: Unknown RR type '${opts.rrtype}'`);
        process.exit(1);
    }

    return opts;
}

interface ResolverWiring {
    resolver: Resolver;
    method_desc: string;
}

function build_resolver(opts: CLIOptions): ResolverWiring {
    if (opts.method === 'doh') {
        const providers = opts.doh_providers.length > 0
            ? opts.doh_providers
            : default_providers();
        const client = new DoHClient({ providers });
        return {
            resolver: { query: client.resolve.bind(client) },
            method_desc: `DoH (${client.providers().join(', ')})`,
        };
    }
    const servers = opts.auth_servers.length > 0
        ? opts.auth_servers
        : DEFAULT_AUTH_SERVERS;
    const client = new AuthClient({ servers });
    return {
        resolver: { query: client.resolve.bind(client) },
        method_desc: `Auth (${client.servers().join(', ')})`,
    };
}

async function main(): Promise<void> {
    const opts = parse_args(process.argv);

    if (opts.update_root_anchors) {
        try {
            await fetch_and_update_root_anchors(opts.doh_providers);
        } catch (err) {
            console.error(`Error updating root anchors: ${err_message(err)}`);
            process.exit(1);
        }
        return;
    }

    const rrtype = StringToRRType(opts.rrtype);
    const { resolver, method_desc } = build_resolver(opts);

    let records: ResourceRecord[];
    try {
        records = await resolver.query(opts.fqdn, rrtype);
    } catch (err) {
        console.error(`Error resolving ${opts.fqdn} ${opts.rrtype}: ${err_message(err)}`);
        process.exit(1);
    }

    let result: Result | undefined;
    let verify_error: string | undefined;
    if (opts.dnssec) {
        const verifier = new Verifier({ resolver });
        try {
            result = await verifier.validate(opts.fqdn, rrtype);
        } catch (err) {
            verify_error = err_message(err);
        }
    }

    console.log(format_output({
        fqdn: opts.fqdn,
        rrtype: opts.rrtype,
        method_desc,
        records,
        result,
        verify_error,
    }));
}

main().catch((err: unknown) => {
    console.error(`Fatal error: ${err_message(err)}`);
    process.exit(1);
});
