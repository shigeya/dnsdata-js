import { StringToRRType, RRTypeToString } from '../lib/dns_type_table';
import { Resolver } from './resolver';
import { DoHResolver, DoHProvider } from './resolver_doh';
import { DNSResolver } from './resolver_dns';
import { formatOutput } from './output';
import { verifyDNSSEC, verifyDNSSECChain } from './dnssec_verifier';
import { fetchAndUpdateRootAnchors } from './root_anchor_updater';

interface CLIOptions {
    method: 'dns' | 'doh';
    dohProvider: DoHProvider;
    dnssec: boolean;
    chain: boolean;
    updateRootAnchors: boolean;
    fqdn: string;
    rrtype: string;
}

function printUsage(): void {
    console.log(`Usage: npx ts-node src/cli/main.ts [options] <fqdn> <rrtype>
       npx ts-node src/cli/main.ts --update-root-anchors [--doh-provider google|cloudflare]

Options:
  --method dns|doh              Resolution method (default: doh)
  --doh-provider google|cloudflare  DoH provider (default: google)
  --no-dnssec                   Skip DNSSEC verification
  --chain                       Full DNSSEC chain verification (root to zone)
  --update-root-anchors         Fetch IANA root trust anchors and save locally
  --help                        Show this help

Examples:
  npx ts-node src/cli/main.ts example.com A
  npx ts-node src/cli/main.ts --chain example.com A
  npx ts-node src/cli/main.ts --chain --doh-provider cloudflare example.com AAAA
  npx ts-node src/cli/main.ts --method dns example.com MX
  npx ts-node src/cli/main.ts --no-dnssec example.com TXT
  npx ts-node src/cli/main.ts --update-root-anchors`);
}

function parseArgs(argv: string[]): CLIOptions {
    const args = argv.slice(2); // skip node and script path
    const opts: CLIOptions = {
        method: 'doh',
        dohProvider: 'google',
        dnssec: true,
        chain: false,
        updateRootAnchors: false,
        fqdn: '',
        rrtype: '',
    };

    const positional: string[] = [];
    let i = 0;
    while (i < args.length) {
        const arg = args[i];
        if (arg === '--help' || arg === '-h') {
            printUsage();
            process.exit(0);
        } else if (arg === '--method') {
            i++;
            const val = args[i];
            if (val !== 'dns' && val !== 'doh') {
                console.error(`Error: --method must be 'dns' or 'doh', got '${val}'`);
                process.exit(1);
            }
            opts.method = val;
        } else if (arg === '--doh-provider') {
            i++;
            const val = args[i];
            if (val !== 'google' && val !== 'cloudflare') {
                console.error(`Error: --doh-provider must be 'google' or 'cloudflare', got '${val}'`);
                process.exit(1);
            }
            opts.dohProvider = val;
        } else if (arg === '--no-dnssec') {
            opts.dnssec = false;
        } else if (arg === '--chain') {
            opts.chain = true;
        } else if (arg === '--update-root-anchors') {
            opts.updateRootAnchors = true;
        } else if (arg.startsWith('-')) {
            console.error(`Error: Unknown option '${arg}'`);
            printUsage();
            process.exit(1);
        } else {
            positional.push(arg);
        }
        i++;
    }

    // --update-root-anchors doesn't need positional args
    if (opts.updateRootAnchors) {
        return opts;
    }

    if (positional.length < 2) {
        console.error('Error: <fqdn> and <rrtype> are required');
        printUsage();
        process.exit(1);
    }

    opts.fqdn = positional[0];
    opts.rrtype = positional[1].toUpperCase();

    // Validate rrtype
    try {
        StringToRRType(opts.rrtype);
    } catch {
        console.error(`Error: Unknown RR type '${opts.rrtype}'`);
        process.exit(1);
    }

    // --no-dnssec and --chain are mutually exclusive
    if (!opts.dnssec && opts.chain) {
        console.error('Error: --no-dnssec and --chain are mutually exclusive');
        process.exit(1);
    }

    return opts;
}

async function main(): Promise<void> {
    const opts = parseArgs(process.argv);

    // Handle --update-root-anchors
    if (opts.updateRootAnchors) {
        try {
            await fetchAndUpdateRootAnchors(opts.dohProvider);
        } catch (err: any) {
            console.error(`Error updating root anchors: ${err.message}`);
            process.exit(1);
        }
        return;
    }

    const rrtype = StringToRRType(opts.rrtype);

    // Create resolver
    let resolver: Resolver;
    if (opts.method === 'doh') {
        resolver = new DoHResolver(opts.dohProvider);
    } else {
        resolver = new DNSResolver();
    }

    // Resolve
    let response;
    try {
        response = await resolver.resolve(opts.fqdn, rrtype);
    } catch (err: any) {
        console.error(`Error resolving ${opts.fqdn} ${opts.rrtype}: ${err.message}`);
        process.exit(1);
    }

    // DNSSEC verification
    let verification;
    if (opts.dnssec && response.answers.length > 0) {
        // For DNSSEC verification, we need DoH results (with RRSIG records)
        let dohResponse = response;
        if (opts.method !== 'doh') {
            // Re-query via DoH to get RRSIG records
            const doh = new DoHResolver(opts.dohProvider);
            try {
                dohResponse = await doh.resolve(opts.fqdn, rrtype);
            } catch (err: any) {
                console.error(`Warning: DNSSEC verification failed (DoH fallback error: ${err.message})`);
                dohResponse = response;
            }
        }
        try {
            if (opts.chain) {
                verification = await verifyDNSSECChain(opts.fqdn, rrtype, dohResponse, opts.dohProvider);
            } else {
                verification = await verifyDNSSEC(opts.fqdn, rrtype, dohResponse, opts.dohProvider);
            }
        } catch (err: any) {
            console.error(`Warning: DNSSEC verification error: ${err.message}`);
        }
    }

    // Output
    const output = formatOutput(
        {
            fqdn: opts.fqdn,
            rrtype: opts.rrtype,
            method: opts.method,
            provider: opts.dohProvider,
        },
        response,
        verification,
    );
    console.log(output);
}

main().catch((err) => {
    console.error(`Fatal error: ${err.message}`);
    process.exit(1);
});
