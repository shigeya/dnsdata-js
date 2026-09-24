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

### Added

- RFC 3597 unknown types (port of dnsdata-go UP-010). `StringToRRType` /
  `StringToRRClass` accept `TYPE<n>` / `CLASS<n>` (case-insensitive);
  new `RRTypeName` / `RRClassName` never throw. New
  `parse_generic_rdata`, `new_resource_record_from_rdata`,
  `ResourceRecord.generic_rdata`, `ResourceRecord.txt_strings`, and
  `format_generic_rdata` (the former `rfc3597`, which stays as an
  alias).
- `tests/testdata/rdata_roundtrip.json`: RDATA round-trip vectors
  shared byte for byte with dnsdata-go.
- `Zone.read_string_strict` and `DNSZoneParseError` (port of dnsdata-go
  UP-011): a master-file reader that rejects, with a line number, what
  `read_string` skips (unknown types or classes, relative owners without
  `$ORIGIN`, missing TTL, malformed or length-mismatched RDATA, types
  with no encoder, unsupported directives). The zone is left untouched
  on error; `read_string` is unchanged.
- `Zone.records_canonical`, `Zone.print_canonical` and
  `compare_canonical_names` (port of dnsdata-go UP-012): RFC 4034 §6
  canonical order (owner, type, class, RDATA octets) with exact
  duplicates removed. The DNSSEC helper of the same name now delegates
  to it with identical results; `print` is unchanged.
- Zone signer `signer` (port of dnsdata-go UP-013, `dnssec/signer`),
  exported as a namespace from the package entry point:
  `signer.generate_key` (algorithms 13, 14, 15, 8, 10, via Node
  `crypto`), `signer.new_key`, `signer.parse_pkcs8_pem` /
  `Key.pkcs8_pem`, `signer.parse_bind_private` (BIND `K*.private`,
  reusing `dnssec_key_loader`); `Key.ds` / `Key.anchor_ds` (digest
  types 2 and 4) and `signer.root_anchors` for a self-made root usable
  as the verifier's `trustAnchors`; `signer.build_nsec` and
  `signer.sign_zone` (KSK/ZSK split or CSK, NSEC chain, delegations and
  glue handled, RRSIG Labels per RFC 4034 §3.1.3 so the root and
  wildcards are right; the existing dot-counting `RRSig` constructor is
  unchanged). `sign_zone` returns a new zone, leaves its input alone,
  drops RRSIG / NSEC / NSEC3 / NSEC3PARAM before re-signing, and
  requires `inception` / `expiration` (the signer never reads the
  clock). Errors are `SignerError` and its subclasses
  `SignerKeyFormatError` / `SignerUnsupportedAlgorithmError`. Like the
  Go side, `sign_zone` and `build_nsec` register the bundled RR handlers
  themselves (the same, idempotent registration as
  `registerAllHandlers`), so they work without a prior
  `registerAllHandlers()` call. Tests cross-check keys, DS and signed
  zones with BIND's `dnssec-keygen`, `dnssec-dsfromkey`,
  `named-checkzone` and `dnssec-verify` when those are on `PATH`.

### Fixed

- A value in `\# <len> <hex>` form is written verbatim by
  `get_wire_body` for any type, ahead of any handler. Previously
  TLSA / SMIMEA / SVCB / HTTPS / unknown RDATA received from the wire
  encoded to nothing, so a correctly signed RRset of those types
  validated as bogus. `get_handler` decodes such values by type.
- `DNSSecZone.sign_rr`, `find_rrsigs`, RRSIG presentation, NSEC / NSEC3
  bitmaps, `ResourceRecord.to_string` and the DoH / authoritative
  resolvers no longer throw on types or classes without a mnemonic.
- RRSIG digest target orders RRset members by RDATA alone and removes
  duplicate RRs (RFC 4034 §6.3, dnsdata-go UF-005). Previously the
  RDLENGTH prefix took part in the sort, so RRsets whose members differ
  in length (NS sets with names of different lengths, TXT, DNSKEY sets
  mixing key sizes) failed to verify against signatures made by other
  signers, and a duplicated record made its RRset unverifiable. A member
  that encodes to nothing now throws `DNSZoneRDataFormatError` instead
  of contributing an empty entry.
- The verifier enforces the RRSIG validity window against its clock
  (RFC 4035 §5.3.1, dnsdata-go UF-006). **Behaviour change:** an expired
  or not-yet-valid signature now yields `Bogus`; previously the `now`
  option of `VerifierOptions` was accepted and ignored, so such chains
  could validate as `Secure`. New `DNSSecZone.set_clock`; without it a
  `DNSSecZone` does not check the window, as before.

## [0.6.0] — 2026-05-20

Coordinated release with dnsdata-go v0.6.0 and mailsec-probe v0.6.0.
Skips v0.5.0: the sibling dnsdata-go used the v0.5.0-rc.1 tag during
UP-009 development and we jump directly to v0.6.0 to keep version
numbers aligned across the two libraries (the alignment is documented
in the CHANGELOG preamble).

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
