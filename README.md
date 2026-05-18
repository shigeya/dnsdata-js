# dnsdata-js

A low-level DNS and DNSSEC protocol library for TypeScript.

`dnsdata-js` handles wire format encoding/decoding, zone file parsing, DNSSEC signature verification and chain validation, and a wide range of resource record types. It is intended for building DNS tools, validators, custom resolvers, and protocol experiments where direct control over wire-level details matters more than a turnkey resolver API.

A sibling Go implementation, [`dnsdata-go`](https://github.com/shigeya/dnsdata-go), is being developed in parallel. The two share the `~/.dnsdata/` on-disk location so root trust anchors and similar artifacts are interoperable.

> **Status: pre-release (`0.0.1`).** The API is still evolving — expect breaking changes before `1.0`. Not yet published to npm; install from source.

## Highlights

- **No external crypto.** All DNSSEC signing and verification goes through Node's built-in `crypto` module.
- **Wide algorithm coverage.** RSA/SHA-1, RSA/SHA-256, RSA/SHA-512, ECDSA P-256, ECDSA P-384, Ed25519, Ed448.
- **Full DNSSEC chain verification.** Validate from the IANA root trust anchor down to any zone, with KSK/ZSK separation, DS digest checks (SHA-1/256/384), and any-valid RRSIG semantics per RFC 4035 §5.3.3.
- **Zone file parser.** Supports `$ORIGIN`, `$TTL`, comments, parenthesized continuation lines, implicit class/labels.
- **Binary correctness.** All wire format uses `Uint8Array`; `Buffer` only appears at Node crypto boundaries.
- **Resource record breadth.** Common, DNSSEC, and modern types — see below.

### Supported record types

| Category | Types |
|---|---|
| Common | A, AAAA, NS, PTR, SOA, MX, TXT, SRV, CAA |
| DNSSEC | DNSKEY, RRSIG, DS, NSEC, NSEC3, NSEC3PARAM, CDS, CDNSKEY |
| Modern | CERT, CSYNC, DANE (TLSA, SMIMEA), EUI48, EUI64, HINFO, LOC, NAPTR, OPENPGPKEY, OPT, RP, SSHFP, SVCB, HTTPS, URI |

New RR types are added by implementing a `ResourceRecordHandler` and registering it with `register_rr_handler()` at module load time. See [`src/lib/dnssec_rr.ts`](packages/core/src/lib/dnssec_rr.ts) for examples.

## Heritage

Ported from `wide-cpp-lib`, a C++ DNS library by Shigeya Suzuki used in research and operational contexts. This TypeScript implementation preserves the layered design and naming (e.g. `ns_type`, `ns_class`, the handler registry pattern) so cross-referencing the two codebases is straightforward.

## Installation

The package is not yet published to npm. To use from source:

```bash
git clone https://github.com/shigeya/dnsdata-js.git
cd dnsdata-js
npm install
cd packages/core
npm install
```

Requirements: Node.js 14 or newer.

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

For DNSSEC validation, populate a `DNSSecZone` with DNSKEY, RRSIG, DS, and the target RRset, then call `verify_rrset()` / `verify_delegation_signer()`. The [`dnssec_zone.spec.ts`](packages/core/tests/lib/dnssec_zone.spec.ts) test file is the most complete usage reference.

## CLI

A `dig`-style CLI lives in [`packages/core/src/cli/`](packages/core/src/cli/). It is not yet packaged as a standalone binary — run it via `ts-node`:

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

This is a [Lerna](https://lerna.js.org/) monorepo. Currently it contains a single package:

| Package | Path | Description |
|---|---|---|
| `@dnsdata/core` | [`packages/core/`](packages/core/) | Wire format, zone parser, DNSSEC verifier, DoH resolver, CLI |

For deeper detail on the internals, the module layout, and the design patterns (handler registry, any-valid RRSIG semantics, etc.), see [`CLAUDE.md`](CLAUDE.md).

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

The test suite currently has **269 tests across 22 suites** covering wire format, zone parsing, DNSSEC verification (all supported algorithms), key tag computation, DS digest validation, and every supported RR type.

## Related

- **[dnsdata-go](https://github.com/shigeya/dnsdata-go)** — Go sibling implementation. Shares the `~/.dnsdata/` user-data location with this project.

## Sibling implementation

`dnsdata-js` and [`dnsdata-go`](https://github.com/shigeya/dnsdata-go) are sibling implementations of the same library, maintained side-by-side. Both are first-class implementations — neither is permanently "upstream":

- Either side may **originate** a new feature; the originating side is the reference for that feature's behaviour until both sides ship.
- Bug-fix feedback flows both directions (Go ↔ TS) via each repo's `UPSTREAM_FEEDBACK.md`.
- Public API surface, wire output, and presentation strings are kept **byte-for-byte equivalent**, even where each language's idioms differ (e.g. `context.Context` ↔ `AbortSignal`, sentinel errors ↔ `instanceof` subclasses, `[]byte` ↔ `Uint8Array`).

### Cross-repo module mapping

Each Go file maps to a single TS file so port-backs are mechanical:

| Go (`dnsdata-go`) | TS (`dnsdata-js/packages/core/src/lib/`) | Notes |
|---|---|---|
| `wire/name.go`            | `dns_wire.ts` (encode/decode) | `domain_name2wire`, `wire2domain_name` |
| `wire/name_decompress.go` | `dns_wire.ts` (`parse_domain_name`) | RFC 1035 §4.1.4 compression-pointer decoder |
| `wire/message.go`         | `dns_message.ts`                | `parse_message`, `Header`, `Question`, `RawRR`, `RawMessage` |
| `wire/rdata.go`           | `rdata_decoder.ts`              | `rdata_to_string`, RFC 3597 fallback |
| `zone/rr.go`              | `dns_zone.ts`                   | `ResourceRecord`, `Zone`, handler registry |
| `dnssec/zone.go`          | `dnssec_zone.ts`                | `DNSSecZone`, chain-of-trust verification helpers |
| `dnssec/key.go` / `rrsig.go` / `ds.go` / `nsec.go` | `dnssec_rr.ts` | `DNSKey`, `RRSig`, `DNSRR_DS`, `DNSRR_NSEC`, `DNSRR_NSEC3` |
| `verifier/`               | `verifier.ts`                   | Chain-of-trust walker with pluggable `Resolver` |
| `types/types.go`          | `dns_type_table.ts`             | RR-type / class / rcode tables |

### Drift policy

Drift that is **accepted** (idiomatic translation): control flow, error mechanics, naming case, value-vs-exception conventions, primitive types.

Drift that is **not accepted** (must be kept in sync): API surface (function names, argument order, optionality semantics), output formats (wire bytes, presentation strings), supported RR-type set, error category meanings.

### Feature origin tagging

When you propose or implement a new feature in either repo, label the Issue / PR with the originator:

- *Originated in dnsdata-go vX.Y.Z* — first shipped on the Go side
- *Originated in dnsdata-js vX.Y.Z* — first shipped on the TS side

This makes it easy to find the reference implementation at any later point.

## License

MIT. See [LICENSE](LICENSE).

## Acknowledgements

The design, implementation, and documentation in this repository were produced in collaboration with [Claude Opus 4.7](https://www.anthropic.com/claude) running inside [Claude Code](https://www.anthropic.com/claude-code).

