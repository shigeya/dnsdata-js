# dnsdata-js

A low-level DNS and DNSSEC protocol library for TypeScript.

`dnsdata-js` handles wire format encoding/decoding, zone file parsing,
DNSSEC signature verification and chain validation, and a wide range of
resource record types. Intended for building DNS tools, validators, custom
resolvers, and protocol experiments where direct control over wire-level
details matters more than a turnkey resolver API.

A sibling Go implementation,
[`dnsdata-go`](https://github.com/shigeya/dnsdata-go), is being developed
in parallel. The two share the `~/.dnsdata/` on-disk location so root
trust anchors and similar artifacts are interoperable.

> **Status: pre-release (`0.0.1`).** The API is still evolving — expect
> breaking changes before `1.0`. Not yet published to npm; install from
> source.

## Highlights

- **No external crypto.** All DNSSEC signing and verification goes through
  Node's built-in `crypto` module.
- **Wide algorithm coverage.** RSA/SHA-1, RSA/SHA-256, RSA/SHA-512,
  ECDSA P-256, ECDSA P-384, Ed25519, Ed448.
- **Full DNSSEC chain verification.** Validate from the IANA root trust
  anchor down to any zone, with KSK/ZSK separation, DS digest checks
  (SHA-1/256/384), and any-valid RRSIG semantics per RFC 4035 §5.3.3.
- **Binary correctness.** All wire format uses `Uint8Array`; `Buffer` only
  appears at Node crypto boundaries.

For the full list of supported RR types, library API examples, and CLI
usage, see [`docs/USAGE.md`](docs/USAGE.md).

## Heritage

Ported from `wide-cpp-lib`, a C++ DNS library by Shigeya Suzuki used in
research and operational contexts. This TypeScript implementation
preserves the layered design and naming (e.g. `ns_type`, `ns_class`, the
handler registry pattern) so cross-referencing the two codebases is
straightforward.

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

## Quick start

```typescript
import { DNSSecZone } from './packages/core/src/lib/dnssec_zone';
import './packages/core/src/lib/dnssec_rr';

const zone = new DNSSecZone();
zone.read_string(`
$ORIGIN example.com.
$TTL 3600
@   IN  SOA   ns1.example.com. admin.example.com. (
              2024010101 7200 3600 1209600 3600 )
    IN  NS    ns1.example.com.
ns1 IN  A     192.0.2.1
`);
console.log(zone.find_rrset('ns1.example.com.', 1).map((rr) => rr.value));
```

See [`docs/USAGE.md`](docs/USAGE.md) for DNSSEC validation, CLI usage,
and full examples.

## Test

```bash
cd packages/core && npx jest
```

269 tests across 22 suites covering wire format, zone parsing, DNSSEC
verification (all supported algorithms), and every supported RR type.

## Documentation

- [`docs/USAGE.md`](docs/USAGE.md) — library API, CLI, supported RR
  types, development commands.
- [`docs/SIBLING.md`](docs/SIBLING.md) — sibling-implementation model,
  cross-repo module mapping, drift policy, TS-specific surface.
- [`CLAUDE.md`](CLAUDE.md) — module-by-module internals and design
  patterns.

## Related

- **[dnsdata-go](https://github.com/shigeya/dnsdata-go)** — Go sibling
  implementation. Shares the `~/.dnsdata/` user-data location with this
  project.

## License

MIT. See [LICENSE](LICENSE).

## Acknowledgements

The design, implementation, and documentation in this repository were
produced in collaboration with
[Claude Opus 4.7](https://www.anthropic.com/claude) running inside
[Claude Code](https://www.anthropic.com/claude-code).
