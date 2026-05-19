# Sibling implementation

`dnsdata-js` and [`dnsdata-go`](https://github.com/shigeya/dnsdata-go) are
sibling implementations of the same library, maintained side-by-side. Both
are first-class implementations — neither is permanently "upstream".

The cross-repo design contract, source-of-truth assignments, and the
overall port-back policy are described in the workspace-level
[`dnsdata-workspace` `DESIGN.md`](https://github.com/shigeya/dnsdata-workspace/blob/main/DESIGN.md).
This document captures the TS-side view of the sibling relationship.

## Origination

Either side may **originate** a new feature; the originating side is the
reference for that feature's behaviour until both sides ship.

- The wire-format codec, zone-file parser, and DNSSEC RR handlers (DNSKEY,
  RRSIG, DS, NSEC, NSEC3) **originated in `dnsdata-js`**.
- The chain validator, DNS message parser + RDATA presentation decoders,
  authoritative-DNS client, NSEC / NSEC3 negative-proof primitives,
  CNAME / DNAME chasing, and wildcard-synthesised positive-answer support
  all **originated in `dnsdata-go`** (v0.1.0 – v0.2.0) and are tracked
  here as
  [#5](https://github.com/shigeya/dnsdata-js/issues/5) –
  [#10](https://github.com/shigeya/dnsdata-js/issues/10).
- UP-001, UP-002, and UP-003 have since been ported back in PRs
  [#17](https://github.com/shigeya/dnsdata-js/pull/17),
  [#19](https://github.com/shigeya/dnsdata-js/pull/19), and the PR closing
  [#7](https://github.com/shigeya/dnsdata-js/issues/7); UP-004 through
  UP-006 are queued.
- The robustness fixes catalogued as UF-001..004 in the Go-side
  `UPSTREAM_FEEDBACK.md` landed here through PRs
  [#11](https://github.com/shigeya/dnsdata-js/pull/11),
  [#14](https://github.com/shigeya/dnsdata-js/pull/14),
  [#15](https://github.com/shigeya/dnsdata-js/pull/15), and
  [#16](https://github.com/shigeya/dnsdata-js/pull/16).

Cross-repo feedback flows both directions. The Go side maintains
[`UPSTREAM_FEEDBACK.md`](https://github.com/shigeya/dnsdata-go/blob/main/UPSTREAM_FEEDBACK.md)
as the Go-side catalogue (Go → TS items). A mirror catalogue for TS-side
observations is not yet a dedicated file in this repo; for now, file
TS-originated proposals or bug observations as issues directly here.

Public API surface, wire output, and presentation strings are kept
**byte-for-byte equivalent** where the contract is defined, even where
each language's idioms differ (e.g. `AbortSignal` ↔ `context.Context`,
`instanceof` subclasses ↔ sentinel errors, `Uint8Array` ↔ `[]byte`,
`snake_case` ↔ `CamelCase`).

## Cross-repo module mapping

Each Go file maps to a single TS file (and vice versa) so port-backs are
mechanical:

| Go (`dnsdata-go`) | TS (`packages/core/src/lib/`) | Notes |
|---|---|---|
| `wire/name.go`                            | `dns_wire.ts` (encode/decode)        | `domain_name2wire`, `wire2domain_name` |
| `wire/name_decompress.go`                 | `dns_wire.ts` (`parse_domain_name`)  | RFC 1035 §4.1.4 compression-pointer decoder |
| `wire/message.go`                         | `dns_message.ts`                     | `parse_message`, `Header`, `Question`, `RawRR`, `RawMessage` |
| `wire/rdata.go`                           | `rdata_decoder.ts`                   | `rdata_to_string`, RFC 3597 fallback |
| `zone/rr.go`, `zone/zone.go`              | `dns_zone.ts`                        | `ResourceRecord`, `Zone`, handler registry |
| `dnssec/zone.go`                          | `dnssec_zone.ts`                     | `DNSSecZone`, chain-of-trust verification helpers, canonical digest target |
| `dnssec/{dnskey,rrsig,ds,nsec,nsec3}.go`  | `dnssec_rr.ts`                       | `DNSKey`, `RRSig`, `DNSRR_DS`, `DNSRR_NSEC`, `DNSRR_NSEC3` |
| `verifier/`                               | `verifier.ts`                        | Chain-of-trust walker with pluggable `Resolver` |
| `types/`                                  | `dns_type_table.ts`                  | RR-type / class / rcode / algorithm tables |
| `dnssec/anchors.go`                       | `dnssec_key_loader.ts`, `root_anchors.ts` | Root trust anchors |
| `resolver/auth/`                          | `resolver_auth.ts`                   | UDP / TCP authoritative-DNS client with TC-fallback + failover (UP-003 / [#7](https://github.com/shigeya/dnsdata-js/issues/7)) |
| (distributed via per-package `errors.go`) | `dns_exception.ts`                   | TS-specific exception hierarchy (`DNSWireError`, `UnknownOpCodeError`, …); Go uses sentinel `errors.Is`-friendly vars per package |
| (folded into `wire/` package)             | `dns_wire_util.ts`                   | TS-specific wire helpers; folded into Go's `wire/` package |
| (not yet ported)                          | `rr/*.ts`                            | Modern RR handlers (CERT, CSYNC, DANE/TLSA/SMIMEA, EUI48/64, HINFO, LOC, NAPTR, OPENPGPKEY, OPT, RP, SSHFP, SVCB/HTTPS, URI) — TS only at this time |

## Drift policy

Drift that is **accepted** (idiomatic translation): control flow, error
mechanics (TS `class extends Error` vs Go sentinel `var`), naming case
(`snake_case` vs `CamelCase`), value-vs-exception conventions, primitive
types (`Uint8Array` vs `[]byte`), cancellation surface (`AbortSignal` vs
`context.Context`), async surface (`Promise<T>` vs synchronous return with
Go-side goroutine concurrency).

Drift that is **not accepted** (must be kept in sync): API surface (function
names, argument order, optionality semantics), output formats (wire bytes,
presentation strings), supported RR-type set, error category meanings,
DNSSEC verdict spellings (`"secure"` / `"secure-nodata"` /
`"secure-nxdomain"` / `"insecure"` / `"bogus"` / `"indeterminate"`).

## TS-specific surface

A few aspects of the TS implementation have no direct Go analogue and are
intentional language-idiomatic choices:

- **Import-time handler registry.** Importing
  [`dnssec_rr.ts`](../packages/core/src/lib/dnssec_rr.ts) registers the
  DNSSEC RR handlers as a side effect of module load via
  `register_rr_handler()`. The Go side requires an explicit
  `dnssec.RegisterHandlers()` call from the constructor because the Go
  project forbids side effects from `init()`.
- **Node `crypto` module.** All DNSSEC signing/verification goes through
  Node's built-in `crypto`. The Go side uses `crypto/...` standard
  library packages directly (`crypto/rsa`, `crypto/ecdsa`,
  `crypto/ed25519`, `crypto/sha256`, …).
- **Lerna monorepo layout.** Sources live under `packages/core/src/lib/`
  with flat file names (e.g. `dns_wire.ts`). The Go side uses package
  directories (`wire/`, `dnssec/`, …) with shorter file names per
  package.
- **TypeScript exception hierarchy.** Errors are subclasses of `Error`
  (`DNSWireError`, `UnknownOpCodeError`, `DNSZoneRDataFormatError`, …)
  living in `dns_exception.ts`; callers discriminate via `instanceof`.
  Go uses sentinel `var Err…` values in per-package `errors.go` files;
  callers discriminate via `errors.Is`.
- **Modern RR handler set.** TS ships handlers for CERT, CSYNC,
  DANE (TLSA, SMIMEA), EUI48/64, HINFO, LOC, NAPTR, OPENPGPKEY, OPT,
  RP, SSHFP, SVCB/HTTPS, and URI under `packages/core/src/lib/rr/`.
  Go has not yet ported these — its current focus is the DNSSEC chain
  primitives and the verifier.

## Feature origin tagging

When you propose or implement a new feature in either repo, label the
Issue / PR with the originator:

- *Originated in dnsdata-js vX.Y.Z* — first shipped on the TS side
- *Originated in dnsdata-go vX.Y.Z* — first shipped on the Go side

This makes it easy to find the reference implementation at any later point.
[Issues #5 – #10](https://github.com/shigeya/dnsdata-js/issues?q=is%3Aissue+UP-)
carry this tag at the top of their bodies for the six Go-originated
features tracked here.
