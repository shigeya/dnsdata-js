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
- UP-001 through UP-006 have since been ported back in PRs
  [#17](https://github.com/shigeya/dnsdata-js/pull/17),
  [#19](https://github.com/shigeya/dnsdata-js/pull/19),
  [#21](https://github.com/shigeya/dnsdata-js/pull/21) –
  [#24](https://github.com/shigeya/dnsdata-js/pull/24). The later
  Go-originated features (UP-007 – UP-015: DoH client, verifier cache,
  resolver response shape, RFC 3597 unknown types, strict reader,
  canonical output, zone signer, in-memory authority, `Result.answer`)
  have landed here too.
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

Both sides use the same package directories, so port-backs are
mechanical. TS paths are relative to `packages/core/src/`:

| Go (`dnsdata-go`) | TS (`packages/core/src/`) | Notes |
|---|---|---|
| `types/`                                  | `types/dns_type_table.ts`, `types/algorithm.ts` | RR-type / class / opcode / rcode / algorithm tables, `TYPE<n>` / `CLASS<n>` (UP-010) |
| `wire/name.go`                            | `wire/dns_wire.ts` (encode/decode)   | `domain_name2wire`, `wire2domain_name` |
| `wire/name_decompress.go`                 | `wire/dns_wire.ts` (`parse_domain_name`) | RFC 1035 §4.1.4 compression-pointer decoder |
| `wire/query.go`                           | `wire/dns_wire.ts` (`build_query`)   | Query builder with EDNS(0) / DO and optional CD (UP-016), shared by the DoH, auth and DoT clients |
| `wire/builder.go`                         | `wire/dns_wire_util.ts`              | Wire builder |
| `wire/message.go`                         | `wire/dns_message.ts`                | `parse_message`, `Header`, `Question`, `RawRR`, `RawMessage` (UP-002) |
| `wire/rdata.go`                           | `wire/rdata_decoder.ts`              | `rdata_to_string`, RFC 3597 fallback (UP-002) |
| `wire/rdata_svcb.go`                      | `wire/rdata_svcb.ts`                 | TLSA / SMIMEA and SVCB / HTTPS presentation (UP-017) |
| (`net.IP.String`)                         | `wire/ip_format.ts`                  | IP address strings for the RDATA decoders |
| `wire/edns.go`                            | `zone/rr/opt_rr.ts`                  | EDNS(0) OPT codec |
| `zone/rr.go`, `zone/zone.go`              | `zone/dns_zone.ts`                   | `ResourceRecord`, `Zone` |
| `zone/registry.go`                        | `zone/registry.ts`                   | `Registry`, `default_registry`, `register_rr_handler` |
| `zone/generic.go`                         | `zone/generic.ts`                    | RFC 3597 `\# <len> <hex>` generic RDATA (UP-010) |
| `zone/strict.go`                          | `zone/strict.ts`                     | Strict master-file reader behind `Zone.read_string_strict` (UP-011) |
| `zone/canonical.go`                       | `zone/canonical.ts`                  | `compare_canonical_names`, canonical sort behind `Zone.records_canonical` (UP-012) |
| `zone/handlers.go`                        | `zone/handlers.ts`                   | Opt-in handler registration |
| `zone/{tlsa,sshfp,openpgpkey,cert,uri,hinfo,rp,eui,csync,loc,naptr,svcb}.go` | `zone/rr/*_rr.ts` | Extended RR handlers (TLSA / SMIMEA are `dane_rr.ts`) |
| `dnssec/zone.go`                          | `dnssec/dnssec_zone.ts`              | `DNSSecZone`, chain-of-trust verification helpers, canonical digest target |
| `dnssec/{dnskey,rrsig,ds,nsec,nsec3}.go`  | `dnssec/{dnskey,rrsig,ds,nsec,nsec3}.ts`, `dnssec/dnssec_rr.ts` | `DNSKey`, `RRSig`, `DNSRR_DS`, `DNSRR_NSEC`, `DNSRR_NSEC3`, NSEC / NSEC3 proof primitives (UP-004) |
| `dnssec/canon.go`                         | `dnssec/dnssec_util.ts`              | Canonical-name compare + `LabelCount` / `LastNLabels` (UP-004) |
| `dnssec/crypto.go`                        | `dnssec/crypto.ts`                   | Signature verification |
| `dnssec/handlers.go`                      | `dnssec/handlers.ts`                 | DNSSEC handler registration |
| `dnssec/sigcheck.go`                      | `dnssec/sigcheck.ts`                 | `SigStatus`, `SigResult`, `rrset_verified` behind `DNSSecZone.check_rrsig` / `check_rrset` |
| `dnssec/signer/key.go`                    | `dnssec/signer/key.ts`               | `Key`, `generate_key`, `new_key`, `parse_pkcs8_pem`, DNSKEY flag constants (UP-013) |
| `dnssec/signer/bind.go`                   | `dnssec/signer/bind.ts`              | `parse_bind_private`, on top of `dnssec_key_loader.ts` (UP-013) |
| `dnssec/signer/ds.go`                     | `dnssec/signer/ds.ts`                | `Key.ds`, `Key.anchor_ds`, `root_anchors` (UP-013) |
| `dnssec/signer/nsec.go`                   | `dnssec/signer/nsec.ts`, `dnssec/signer/names.ts` | `build_nsec`, zone view, name helpers (UP-013) |
| `dnssec/signer/nsec3.go`                  | `dnssec/signer/nsec3.ts`             | `build_nsec3`, `NSEC3Options` (UP-018) |
| `dnssec/signer/sign.go`                   | `dnssec/signer/sign.ts`              | `sign_zone`, `SignOptions`, `rrsig_labels` (in `names.ts`) (UP-013) |
| (sentinel errors in `dnssec/signer/key.go`) | `dnssec/signer/errors.ts`          | `SignerError`, `SignerKeyFormatError`, `SignerUnsupportedAlgorithmError` |
| `verifier/`                               | `verifier/`                          | Chain-of-trust walker with pluggable `Resolver` (UP-001, UP-005, UP-006), `Cache` (UP-008), `Result.answer` (UP-015); `reason.ts` (`ReasonCode`, `result_error`), `sigcheck.ts` (`ZoneStep.signatures`), `events.ts` (`StepEvent`, `StepKind`, `VerifierOptions.onStep`) mirror the same-named Go files |
| `dnssec/anchors.go`                       | `dnssec/dnssec_key_loader.ts`, `dnssec/root_anchors.ts` | Root trust anchors |
| `resolver/resolver.go`                    | `resolver/response.ts`               | `Response { records, ad, rcode }` (UP-009) |
| `resolver/doh/`                           | `resolver/doh/`                      | RFC 8484 DoH client with provider failover (UP-007) |
| `resolver/auth/`                          | `resolver/auth/`                     | UDP / TCP authoritative-DNS client with TC-fallback + failover (UP-003 / [#7](https://github.com/shigeya/dnsdata-js/issues/7)) |
| `resolver/dot/`                           | `resolver/dot/`                      | RFC 7858 DNS-over-TLS client, `DoTClient` (UP-019) |
| `resolver/internal/stream/`               | `resolver/stream.ts`                 | Two-octet length framing on TCP / TLS and the Node socket reader, shared by auth and DoT (UP-019) |
| `resolver/internal/message/`              | `resolver/message.ts`                | Response message → `ResolverResponse`, shared by auth, DoH and DoT (UP-019) |
| (`net.SplitHostPort` / `JoinHostPort`)    | `resolver/addr.ts`                   | `host:port` handling, shared by auth and DoT |
| `resolver/memory/memory.go`               | `resolver/memory/memory.ts`          | `Authority`, `new_authority` (Go `New`), `with_zone`, `with_fault` (UP-014) |
| `resolver/memory/index.go`                | `resolver/memory/zone_index.ts`, `resolver/memory/names.ts` | Per-zone index and name helpers (UP-014) |
| `resolver/memory/answer.go`               | `resolver/memory/answer.ts`          | Referral / answer / CNAME / DNAME / wildcard / NODATA / NXDOMAIN responses (UP-014), NSEC or NSEC3 proofs (UP-018) |
| `resolver/memory/nsec3.go`                | `resolver/memory/nsec3.ts`           | A zone's NSEC3 chain for the proofs (UP-018) |
| (`ErrConfig` in `resolver/memory/memory.go`) | `resolver/memory/errors.ts`       | `MemoryConfigError` |
| `resolver/memory/*_test.go`               | `../tests/resolver/memory/*.spec.ts` | Hierarchy, authority, example and shared-vector tests (UP-014) |
| `testdata/rdata_roundtrip.json`           | `../tests/testdata/rdata_roundtrip.json` | Shared RDATA round-trip vectors; byte-identical, generated on the Go side only (UP-010) |
| `testdata/signed/`                        | `../tests/testdata/signed/`          | Shared signed hierarchy and expected verdicts; byte-identical, generated on the Go side only |
| `testdata/bind/`                          | `../tests/testdata/bind/`            | A zone signed by BIND with mixed-case names (UF-008); byte-identical, copied from the Go side |
| (distributed via per-package `errors.go`) | `dns_exception.ts`                   | TS-specific exception hierarchy (`DNSWireError`, `UnknownOpCodeError`, …); Go uses sentinel `errors.Is`-friendly vars per package |

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

- **Node `crypto` module.** All DNSSEC signing/verification goes through
  Node's built-in `crypto`. The Go side uses `crypto/...` standard
  library packages directly (`crypto/rsa`, `crypto/ecdsa`,
  `crypto/ed25519`, `crypto/sha256`, …).
- **Lerna monorepo layout.** Sources live under `packages/core/src/`
  in the same package directories as the Go side (`wire/`, `zone/`,
  `dnssec/`, …), with a single `registerAllHandlers()` entry point in
  `index.ts` where Go has per-package `RegisterHandlers()`.
- **TypeScript exception hierarchy.** Errors are subclasses of `Error`
  (`DNSWireError`, `UnknownOpCodeError`, `DNSZoneRDataFormatError`, …)
  living in `dns_exception.ts`; callers discriminate via `instanceof`.
  Go uses sentinel `var Err…` values in per-package `errors.go` files;
  callers discriminate via `errors.Is`.

## Feature origin tagging

When you propose or implement a new feature in either repo, label the
Issue / PR with the originator:

- *Originated in dnsdata-js vX.Y.Z* — first shipped on the TS side
- *Originated in dnsdata-go vX.Y.Z* — first shipped on the Go side

This makes it easy to find the reference implementation at any later point.
[Issues #5 – #10](https://github.com/shigeya/dnsdata-js/issues?q=is%3Aissue+UP-)
carry this tag at the top of their bodies for the six Go-originated
features tracked here.
