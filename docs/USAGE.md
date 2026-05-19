# Usage

Library and CLI usage details for `dnsdata-js`. For a high-level overview
see [`README.md`](../README.md); for cross-repo design see
[`SIBLING.md`](./SIBLING.md).

## Supported record types

| Category | Types |
|---|---|
| Common | A, AAAA, NS, PTR, SOA, MX, TXT, SRV, CAA |
| DNSSEC | DNSKEY, RRSIG, DS, NSEC, NSEC3, NSEC3PARAM, CDS, CDNSKEY |
| Modern | CERT, CSYNC, DANE (TLSA, SMIMEA), EUI48, EUI64, HINFO, LOC, NAPTR, OPENPGPKEY, OPT, RP, SSHFP, SVCB, HTTPS, URI |

New RR types are added by implementing a `ResourceRecordHandler` and
registering it with `register_rr_handler()` at module load time. See
[`packages/core/src/lib/dnssec_rr.ts`](../packages/core/src/lib/dnssec_rr.ts)
for examples.

## Library usage

Until the package is published, import from the source paths:

```typescript
import { DNSSecZone } from './packages/core/src/lib/dnssec_zone';
// or, from within the monorepo:
// import { DNSSecZone } from '../../src/lib/dnssec_zone';

// Bring in the DNSSEC RR handlers (registers DNSKEY/RRSIG/DS/NSEC/NSEC3 on load)
import './packages/core/src/lib/dnssec_rr';

const zoneText = `
$ORIGIN example.com.
$TTL 3600
@       IN  SOA   ns1.example.com. admin.example.com. (
                  2024010101 7200 3600 1209600 3600 )
        IN  NS    ns1.example.com.
ns1     IN  A     192.0.2.1
`;

const zone = new DNSSecZone();
zone.read_string(zoneText);

const a_rrs = zone.find_rrset('ns1.example.com.', /* RRType.A */ 1);
console.log(a_rrs.map((rr) => rr.value));
```

For DNSSEC validation, populate a `DNSSecZone` with DNSKEY, RRSIG, DS, and
the target RRset, then call `verify_rrset()` / `verify_delegation_signer()`.
The
[`dnssec_zone.spec.ts`](../packages/core/tests/lib/dnssec_zone.spec.ts)
test file is the most complete usage reference.

## CLI

A `dig`-style CLI lives in
[`packages/core/src/cli/`](../packages/core/src/cli/). It is not yet
packaged as a standalone binary — run it via `ts-node`:

```bash
cd packages/core

# A lookup via DoH (default: Google), with DNSSEC verification
npx ts-node src/cli/main.ts example.com A

# Full chain verification (root → zone)
npx ts-node src/cli/main.ts --chain example.com A

# Cloudflare DoH instead of Google
npx ts-node src/cli/main.ts --doh-provider cloudflare example.com AAAA

# System resolver instead of DoH
npx ts-node src/cli/main.ts --method dns example.com MX

# Skip DNSSEC
npx ts-node src/cli/main.ts --no-dnssec example.com TXT

# Refresh IANA root trust anchors (saved to ~/.dnsdata/root-anchors.json)
npx ts-node src/cli/main.ts --update-root-anchors
```

User data location: `~/.dnsdata/` — shared with `dnsdata-go`.

## Architecture

This is a [Lerna](https://lerna.js.org/) monorepo. Currently it contains a
single package:

| Package | Path | Description |
|---|---|---|
| `@dnsdata/core` | [`packages/core/`](../packages/core/) | Wire format, zone parser, DNSSEC verifier, DoH resolver, CLI |

For module-by-module internals (handler registry, any-valid RRSIG semantics,
crypto algorithm mapping, etc.) see [`CLAUDE.md`](../CLAUDE.md).

## Development

```bash
cd packages/core

# Run all tests
npx jest

# Run a single test file
npx jest tests/lib/dns_wire.spec.ts

# Type check
npx tsc

# Lint
npx eslint src/ tests/
```

The test suite currently has **269 tests across 22 suites** covering wire
format, zone parsing, DNSSEC verification (all supported algorithms), key
tag computation, DS digest validation, and every supported RR type.
