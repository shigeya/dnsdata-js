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

## [0.8.0] — 2026-10-03

Coordinated release with dnsdata-go v0.8.0 (port-back of UP-016 –
UP-019 and UF-007). Transports and signing: a DNS-over-TLS client, the
CD bit on queries, NSEC3 signing with NSEC3 proofs from the memory
authority, and the message parser and RDATA decoder exported from the
entry point. No API is removed, but presentation and verdicts change:
TLSA / SMIMEA / SVCB / HTTPS RDATA is presented by type instead of
`\#`, TXT and CAA use `\DDD` escapes and present UTF-8 as text, and
alias and negative-proof fixes change the verdict of DNAME answers,
alias answers from recursive resolvers and wildcard NODATA. Answers the
clients received now sign as the octets they arrived as, so TLSA / SVCB
validation needs only the DNSSEC handlers registered.

### Added

- `new_resource_record_with_rdata` (and an optional `rdata` argument
  on the `ResourceRecord` constructor): a record with its presentation
  value and the RDATA octets it was received as. `get_wire_body` writes
  those octets when no handler or built-in encoder exists for the type.
  The DoH / auth / DoT clients build their records with it. Ports
  dnsdata-go's `zone.NewResourceRecordWithRData`.
- The package entry point exports the DNS message parser and the
  RDATA presentation decoder: `parse_message`, `Header`, the
  `Question` / `RawRR` / `RawMessage` types, and `rdata_to_string`.
- `FLAG_CD`, `QueryOptions` and `build_query_with_options`: a query with
  the CD (checking disabled) bit, RFC 4035 §3.2.2. `checking_disabled`
  on `DoHClientOptions` and `AuthClientOptions` sets it on every query,
  so a validating upstream returns data it would reject as bogus
  instead of SERVFAIL. Off by default; queries are unchanged. Ports
  dnsdata-go's `WithCheckingDisabled`.
- `nsec3` in `signer.SignOptions` and `signer.build_nsec3`: sign with
  an NSEC3 chain (RFC 5155 §7.1) and an NSEC3PARAM at the apex instead
  of NSEC. `{}` is the RFC 9276 profile (no extra iterations, no
  salt); `iterations`, `salt` and `optOut` (unsigned delegations left
  out of the chain, RFC 5155 §6) are options. NSEC stays the default.
  BIND's `dnssec-verify` accepts both profiles. Ports dnsdata-go.
- The memory authority answers zones signed with NSEC3 with NSEC3
  proofs (RFC 5155 §7.2): NODATA, empty non-terminal, NXDOMAIN,
  wildcard answer and wildcard NODATA, and the referral to a
  delegation without DS, by the matching NSEC3 or, under opt-out, the
  closest provable encloser proof. Ports dnsdata-go.
- `base32hex_encode` is exported from `wire/rdata_decoder`.
- `DoTClient`: a DNS-over-TLS client (RFC 7858) with the shape of the
  auth and DoH clients — `servers` (port 853 by default), `tls` (`ca`,
  `servername`), `timeout_ms`, `checking_disabled`; `query`,
  `query_raw`, and `resolve` returning a `ResolverResponse`. The server
  is authenticated as in RFC 8310 strict privacy (trusted root,
  matching name or address, TLS 1.2 or later). One connection per
  query. Errors are `DoTResolverError` subclasses; `normalize_dot_addr`
  adds the port. Ports dnsdata-go `resolver/dot`.

### Changed

- TXT character-strings and the CAA value use RFC 1035 §5.1 escapes in
  both directions, as in dnsdata-go. `rdata_to_string` writes octets
  that are neither printable ASCII nor part of valid UTF-8 as `\DDD`
  (control characters included); previously they became one code point
  each. Reading a TXT or CAA value, `\DDD` is one octet and `\X` is `X`,
  in quoted strings and bare tokens; previously `\065` read as `065`. A
  `\DDD` above 255 throws `DNSZoneRDataFormatError`. Only space, tab,
  CR and LF separate bare tokens, as in dnsdata-go.
- The CAA value is presented and read like a TXT string, so non-ASCII
  values round-trip (they were presented one code point per octet and
  written back as UTF-8). Shared vectors "TXT control and invalid
  UTF-8" and "CAA non-ASCII and escapes".
- `rdata_to_string` writes TLSA and SMIMEA as `usage selector
  matching-type hex`, and SVCB and HTTPS as `priority target
  key=value ...` (the RFC 9460 mnemonics and `keyNNNNN`, the latter
  with a hex value) instead of the generic `\# <len> <hex>`, as
  dnsdata-go does. Both read back through `ResourceRecord` to the same
  octets; RDATA that would not (keys out of order, an ALPN id with `,`
  or non-ASCII, an IPv4-mapped `ipv6hint`, an uppercase target, empty
  TLSA data) is still generic, as is malformed RDATA. Shared vectors
  "SVCB all keys", "SVCB keys out of order" and "TLSA empty data".
- `AuthClient` writes the TCP length prefix and the query in one write
  (RFC 7766 §8). Its TCP reader, the length framing, the address
  helpers and the conversion of a response into a `ResolverResponse`
  are shared with the DoT client (and the conversion with `DoHClient`);
  results and error messages are unchanged.

### Fixed

- DNAME answers validate. The leaf step tried CNAME before DNAME, and
  the CNAME synthesised from a DNAME has no RRSIG (RFC 6672 §5.3.1), so
  every name below a DNAME was Bogus (dnsdata-go UF-007).
- Alias answers from recursive resolvers validate. The leaf step
  counted records of the asked type regardless of owner, so the alias
  target's RRset in the same answer made the walker verify a qname
  RRset that was not there (UF-007).
- Wildcard NODATA and empty non-terminal NODATA are `secure-nodata`,
  no longer `secure-nxdomain`; an NSEC matching the wildcard is no
  longer taken as its denial. NSEC3 wildcard NODATA (RFC 5155 §8.7) is
  `secure-nodata` instead of `indeterminate` (UF-007).
- `AliasStep.from` of a DNAME hop is the DNAME owner, as documented,
  instead of the name queried in that hop. CNAME hops are unchanged
  (the owner is the queried name). The queried name of a hop is the
  previous hop's `target`.
- `resolver/memory` answers aliases as real authoritative servers do:
  a wildcard CNAME is synthesised for queries of any type (RFC 4592
  §3.3.3), not only CNAME; and a DNAME answer carries the unsigned
  CNAME synthesised from it (RFC 6672 §5.3.1).
- `clone()` of a handler built from RFC 3597 generic RDATA (`\# <len>
  <hex>`) no longer throws. It re-parsed the record's generic value as
  presentation form; it now re-parses the presentation decoded from the
  octets, exposed as `ResourceRecord.handler_value()`.
- A root-anchors file written by dnsdata-go (`"dnskeys": null`, how Go
  encodes an empty list) reads as `dnskeys: []`, matching the
  `RootAnchors` type. New `parseRootAnchors(text)` validates the shape
  and throws `RootAnchorsFormatError`; `loadRootAnchors` uses it and
  still falls back to the built-in anchors on error.
- `rdata_to_string` presents a TXT character-string that is valid UTF-8
  as that text, as dnsdata-go does, instead of one code point per
  octet; the presentation now reads back to the same octets. Other
  octets are presented as before. New shared vector
  "TXT UTF-8 with BOM".
- TLSA, SMIMEA, SVCB and HTTPS answers from the DoH / auth / DoT
  clients validate with only the DNSSEC handlers registered. Since that
  RDATA is presented by type, only the zone handlers could encode it
  back for the RRSIG check, and validation threw "no encoder". The
  clients now keep the received octets on the record
  (`new_resource_record_with_rdata`), and `get_wire_body` writes them
  when no handler or built-in encoder exists for the type. The
  `Verifier` constructor registers nothing. A record that still has no
  encoder fails with an error naming the registration it needs. Shared
  vector `tests/testdata/handlers`, served over UDP.
- A name below a DNAME in a zone signed with opt-out NSEC3 follows the
  DNAME. The walker asked for DS at every ancestor of the query name
  and took an opt-out NSEC3 that happened to cover the name's hash
  (sent as the denial for the DNAME owner) as proof of an unsigned
  delegation, so the verdict was Insecure at the query name with no
  DNAME hop. A name below a DNAME is never a zone cut (RFC 6672 §2.4;
  RFC 6840 §4.1), so no "no DS" proof is sought for it.

## [0.7.0] — 2026-09-24

Coordinated release with dnsdata-go v0.7.0 (port-back of UP-010..015
and UF-005 / UF-006). Zone signing and offline validation: unknown RR
types as first class, a strict zone reader, canonical output, a zone
signer, an in-memory authority, and the validated answer on `Result`.
No API is removed. Two validation fixes change verdicts: RRSIGs outside
their validity window are now Bogus (UF-006), and RRsets whose members
differ in length now verify in canonical order (UF-005).

### Added

- The package entry point now exports the chain validator:
  `Verifier`, `VerifierOptions`, `Verdict`, `Result` and its types,
  `Resolver`, `Cache` / `MemoryCache`, the `Verifier*Error` classes,
  `ResolverResponse`, and the auth client (`AuthClient` and its
  errors). Earlier releases documented `import { Verifier } from
  '@dnsdata/core'` but did not export it.
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
- In-memory authority `memory` (port of dnsdata-go UP-014,
  `resolver/memory`), exported as a namespace from the package entry
  point: `memory.new_authority(memory.with_zone(apex, zone), ...,
  memory.with_fault(name, qtype, rcode))` returns a `memory.Authority`
  implementing the verifier's `Resolver`. The deepest zone holding the
  name answers, and a DS query for an apex goes to the parent; it
  returns referrals (NS plus the signed DS or the NSEC proving none),
  RRsets with their RRSIGs, CNAME, DNAME, wildcard synthesis (owner
  rewritten to the query name, plus the next-closer NSEC), and NODATA /
  NXDOMAIN with their NSEC proofs; REFUSED outside every zone. Responses
  are fresh copies; the authority is immutable. NSEC3 proofs are not
  generated. Configuration errors are `memory.MemoryConfigError`.
  Validation under a private root needs no verifier change
  (`signer.root_anchors` → `trustAnchors`, the clock via `now`); tests
  and a documented example fix that use.
- `tests/testdata/signed/`: a signed private root, `test.` and
  `example.test.` with their BIND test keys, root anchors and expected
  verdicts, shared byte for byte with dnsdata-go and validated to the
  same nine verdicts.
- `Result.answer` (port of dnsdata-go UP-015): the RRset that was
  validated — each record's owner, TTL, class, type, presentation
  `value` and `rdata` (base64 of the RDATA octets the signature
  covered; RFC 3597 form and exact octets for types without a
  mnemonic) — with the RRSIGs over it that verified at the verifier's
  clock (`keyTag`, `algorithm`, `signer`, `labels`, and `inception` /
  `expiration` as RFC 3339 UTC strings). Set only when the verdict is
  `Secure`: after CNAME / DNAME hops it is the terminal RRset, for a
  wildcard answer the synthesised RRset at the query name. Consumers no
  longer need to query the name again. `Result` stays plain JSON and
  matches the Go JSON form; other results are unchanged. New types
  `Answer`, `AnswerRecord`, `AnswerSignature`.

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
