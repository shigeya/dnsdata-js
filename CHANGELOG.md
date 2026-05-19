# Changelog

All notable changes to dnsdata-js are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/).

Version numbers track the
[shigeya/dnsdata-go](https://github.com/shigeya/dnsdata-go) sibling
release that this codebase has reached parity with — both repos are
co-developed under the model described in
[docs/SIBLING.md](docs/SIBLING.md), and aligning the numbers keeps the
"is your TS verifier as featureful as the Go one of the same
version?" question answerable at a glance.

## [Unreleased]

### Changed (BREAKING)

- New `ResolverResponse` shape returned by both `DoHClient.resolve`
  and `AuthClient.resolve`: `{ records, ad, rcode }`. The AD bit and
  RCODE from the parsed wire header are surfaced verbatim so consumers
  no longer need to re-parse the wire message to recover them.
- Non-zero RCODE is no longer thrown as `DoHResponseError` /
  `AuthResponseError`. The resolver layer returns the parsed response
  as data; only transport- and parse-level failures come back as
  errors. Callers that need "any non-zero RCODE is fatal" should
  inspect `resp.rcode` themselves.
- `Resolver.query` (verifier transport) signature updated in lockstep
  to `Promise<ResolverResponse>`. The RCODE classification policy
  moves into `verifier/chain.ts:load_records`: RCODE 0 and 3
  (NXDOMAIN) are treated as "no records present" so the existing
  NODATA / NXDOMAIN proof paths handle them; any other non-zero RCODE
  raises `VerifierResolverError`.

Ports dnsdata-go UP-009.

## [0.4.0] — 2026-05-19

First tagged release of dnsdata-js. The history below back-fills
the milestones that landed before tagging started; future versions
will track changes incrementally.

### Added

- **`verifier`: pluggable `Cache` layer** ([#25](https://github.com/shigeya/dnsdata-js/pull/25), UP-008).
  New `Cache` interface and built-in `MemoryCache` attached via
  `VerifierOptions.cache`. The verifier consults the cache before
  every `Resolver.query` and stores successful responses (including
  NODATA, signalled by an empty array) back into it; resolver errors
  are never cached. Sharing one cache across `validate()` calls lets
  a batch run reuse root and TLD DNSKEY / DS rrsets. Mirrors
  `dnsdata-go` v0.4.0
  ([#21](https://github.com/shigeya/dnsdata-go/pull/21)).
- **Refactor to per-feature packages** mirroring `dnsdata-go`'s
  layout ([#18 P5 through P8](https://github.com/shigeya/dnsdata-js)):
  `packages/core/src/{types,wire,zone,dnssec,resolver,verifier}`
  with the legacy `lib/` shell drained.
- **Wildcard-synthesised positive answer support**
  ([#24](https://github.com/shigeya/dnsdata-js/pull/24), UP-006):
  digest target reconstruction (RFC 4035 §5.3.2) + next-closer
  non-existence proof (§5.3.4), `Result.wildcard` evidence field.
- **CNAME / DNAME chasing with worst-of verdict combination**
  ([#23](https://github.com/shigeya/dnsdata-js/pull/23), UP-005):
  alias-loop detection, `MAX_ALIAS_HOPS` cap, `AliasStep` records.
- **NSEC / NSEC3 negative-proof primitives**
  ([#22](https://github.com/shigeya/dnsdata-js/pull/22), UP-004):
  Insecure-delegation classification, leaf NODATA / NXDOMAIN proofs,
  six-state `Verdict`.
- **UDP + TCP authoritative-DNS client with TC fallback and failover**
  ([#21](https://github.com/shigeya/dnsdata-js/pull/21), UP-003).
- **DNS message wire-format parser + RDATA presentation decoders**
  ([#19](https://github.com/shigeya/dnsdata-js/pull/19), UP-002).
- **DNSSEC chain validator with pluggable Resolver, four-state
  Verdict, and JSON-friendly Result**
  ([#17](https://github.com/shigeya/dnsdata-js/pull/17), UP-001).

### Fixed

- **`MemoryCache` key separator: NUL byte → literal space**
  ([#26](https://github.com/shigeya/dnsdata-js/pull/26)) — typo in
  the original UP-008 commit. No functional impact; restores text
  diffability of `cache.ts`.
- **`get_wire_body` surfaces `DNSZoneRDataFormatError`**
  ([#15](https://github.com/shigeya/dnsdata-js/pull/15), UF-004) —
  previously swallowed the error and emitted nothing.
- **Typed enum-classification errors in `dns_type_table`**
  ([#16](https://github.com/shigeya/dnsdata-js/pull/16), UF-003) —
  callers can now `errors.is(err, DNSTypeUnknownError)` instead of
  catching bare `RangeError`.
- **RFC 1035 label / name length limits enforced**
  ([#14](https://github.com/shigeya/dnsdata-js/pull/14), UF-002).
- **`domain_name2wire` no longer corrupts underscore byte**
  ([#11](https://github.com/shigeya/dnsdata-js/pull/11), UF-001) —
  the `| 0x20` lowercase trick was flipping `_` (0x5F) into `~`
  (0x7F).

### Notes

This is the first release published as a Git tag + GitHub Release.
No npm publish yet. Consumers depending on this code are expected to
vendor or path-pin until an npm story is decided.

The lineage and sibling-implementation contract are documented in
[docs/SIBLING.md](docs/SIBLING.md); per-feature port-back history
lives in
[`dnsdata-go/UPSTREAM_FEEDBACK.md`](https://github.com/shigeya/dnsdata-go/blob/main/UPSTREAM_FEEDBACK.md).
