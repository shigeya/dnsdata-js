# dnsdata-js — Design

## 1. Overview

DNS / DNSSEC primitives and a chain-of-trust validator implemented in
TypeScript, running on Node's built-in `crypto` module.

Lineage:

```
wide-cpp-lib (C++) → dnsdata-js (TypeScript)   ← here
                          ⇅
                     dnsdata-go (Go)
```

`dnsdata-js` and [`dnsdata-go`](https://github.com/shigeya/dnsdata-go)
are now maintained as equal sibling implementations — see
[`docs/SIBLING.md`](docs/SIBLING.md) for the co-development model
(originator tags, drift policy, cross-repo module mapping). Both repos
ship under coordinated version numbers (e.g. `dnsdata-js v0.6.0` =
`dnsdata-go v0.6.0`); the [CHANGELOG](./CHANGELOG.md) preamble records
the alignment policy.

- Package: `@dnsdata/core` (Lerna monorepo, `packages/core/`)
- Runtime: Node.js 14+
- Crypto: Node `crypto` only (`createSign`, `createVerify`, `createHash`,
  `createPublicKey`). No `node-forge`, no `tweetnacl`, no external
  DNSSEC library.
- Wire-format: hand-rolled. No `dns-packet`, no `native-dns-packet`. RR
  type codes are passed as raw `number` (16-bit).
- Primary consumer:
  [`mailsec-probe`](https://github.com/shigeya/mailsec-probe) Phase 3.0,
  via the Go sibling. No direct TS consumer in mailsec-probe today, but
  the public API surface is kept byte-for-byte equivalent so TS callers
  can target the same contract.

## 2. Package layout

Sources live under `packages/core/src/`. The layout was refactored in
v0.4.0 (REFACTOR_PLAN.md §3, P5–P8) to be 1-to-1 with the Go side so
port-backs are mechanical.

| Directory | Role | Go counterpart |
|---|---|---|
| `types/` | RR type / class / opcode / rcode / DNSSEC algorithm enums + bidirectional string conversion | `types/` |
| `wire/` | DNS wire-format codec — names (with RFC 1035 §4.1.4 compression), `WireBuilder`, message parser, per-type RDATA → presentation decoders, query builder | `wire/` |
| `zone/` | Zone-file parser (lenient `read_string` and strict `read_string_strict`), canonical-order output, RFC 3597 generic RDATA, `ResourceRecord`, pluggable RR-type handler registry, legacy RR set under `zone/rr/` | `zone/` |
| `dnssec/` | `DNSKey` / `RRSig` / `DNSRR_DS` / `DNSRR_NSEC` / `DNSRR_NSEC3` handlers, `DNSSecZone`, root trust anchors, canonical-name helpers | `dnssec/` |
| `dnssec/signer/` | Zone signer: key generation and loading, DS / trust-anchor derivation, NSEC chain, `sign_zone` (exported as the `signer` namespace) | `dnssec/signer/` |
| `resolver/doh/` | RFC 8484 DoH client with Cloudflare / Google / Quad9 sequential failover | `resolver/doh/` |
| `resolver/auth/` | UDP + TCP authoritative-DNS client with TC-fallback and multi-server failover | `resolver/auth/` |
| `resolver/memory/` | In-memory authority serving signed zones to the verifier, for tests and private roots (exported as the `memory` namespace) | `resolver/memory/` |
| `verifier/` | DNSSEC chain-of-trust walker (`Verifier.validate(qname, qtype, signal?) → Promise<Result>`) | `verifier/` |
| `cli/` | Reference CLI (`cli/main.ts`); not part of the library public API | (no Go counterpart) |

The exported public surface lives in `packages/core/src/index.ts` and
its barrel re-exports. RR handler installation is **opt-in**: importing
the entry point does NOT register anything. Callers invoke
`registerAllHandlers()` (or the per-package `register_dnssec_handlers`
/ `register_legacy_handlers` helpers) once at startup before
`DNSSecZone` signature checks or `Verifier.validate()` run. The
`Verifier` constructor installs nothing. Records the resolver clients
build keep the RDATA octets they received
(`new_resource_record_with_rdata`), so a TLSA, SMIMEA, SVCB or HTTPS
answer verifies without the zone handlers; the DNSSEC handlers are
still the caller's to register.

## 3. Public API

```typescript
import { Verifier, Verdict, Result } from '@dnsdata/core';
import { DoHClient } from '@dnsdata/core';

const client = new DoHClient();
const verifier = new Verifier({ resolver: client });
const result: Result = await verifier.validate(
    'example.com.',
    /* A */ 1,
    AbortSignal.timeout(5_000),
);
```

```typescript
interface VerifierOptions {
    resolver: Resolver;                     // required transport
    trustAnchors?: RootAnchors;             // overrides IANA roots
    now?: () => Date;                       // clock for the RRSIG validity window
    cache?: Cache;                          // pluggable cache (UP-008)
    registry?: Registry;                    // RR handlers (default: DNSSEC handlers)
    onStep?: (e: StepEvent) => void;        // streamed verification steps
}

class Verifier {
    constructor(opts: VerifierOptions);
    validate(qname: string, qtype: number, signal?: AbortSignal): Promise<Result>;
}

interface Result {
    verdict: Verdict;                       // six-state classification
    chain: ZoneStep[];
    insecureAt?: string;
    insecureReason?: string;
    bogusAt?: string;
    bogusReason?: string;
    negativeReason?: string;
    reasonCode?: ReasonCode;                // Bogus / Insecure; see result_error()
    aliases?: AliasStep[];                  // CNAME / DNAME hops (UP-005)
    wildcard?: WildcardInfo;                // wildcard synthesis (UP-006)
    evidence: Evidence;                     // presentation-form raw data
    answer?: Answer;                        // validated RRset, Secure only (UP-015)
}

interface Answer {
    name: string;
    type: number;
    records: { name: string; ttl: number; class: number; type: number;
               value: string; rdata: string /* base64 */ }[];
    signatures: { keyTag: number; algorithm: number; signer: string; labels: number;
                  inception: string; expiration: string /* RFC 3339 UTC */ }[];
}
```

`answer` is present only when `verdict` is `Verdict.Secure`: after
CNAME / DNAME hops it is the terminal RRset, for a wildcard answer the
synthesised RRset at the query name, and `signatures` lists each RRSIG
over it that verified at the verifier's clock. Per MUST 10 the RDATA
octets are base64 and the window is RFC 3339 strings
(`"2026-01-01T00:00:00Z"`), the same JSON dnsdata-go emits for its
`[]byte` and `time.Time` fields.

The detailed contract is in §4 (Requirements).

## 4. Requirements (mirror of mailsec-probe `DESIGN.md §16`)

The API contract that mailsec-probe (= the consumer) asks the dnsdata
implementations to honor. The source of truth is mailsec-probe's
DESIGN.md §16; it is mirrored on the Go side at
[`dnsdata-go/DESIGN.md §4`](https://github.com/shigeya/dnsdata-go/blob/main/DESIGN.md);
this section is the TS translation.

When this section changes, all three DESIGN.md files (mailsec-probe,
dnsdata-go, dnsdata-js) must be updated together.

Idiom mapping applied:

- `context.Context` → `AbortSignal`
- `(*Result, error)` Go return → `Promise<Result>` that rejects with a
  typed `Error` subclass on failure
- sentinel errors (`errors.Is`) → `Error` subclasses (`instanceof`)
- `[]byte` → `Uint8Array`
- `goroutine-safe` → "safe to use multiple `Verifier` instances
  concurrently from independent async contexts"

### MUST

1. `Verifier.validate(qname, qtype, signal?) → Promise<Result>` is safe
   to call concurrently from multiple async contexts on independent
   `Verifier` instances. A single `Verifier`'s `validate()` itself
   walks the chain sequentially.
2. `Result.verdict` is one of `Verdict.Secure` | `Verdict.SecureNoData`
   | `Verdict.SecureNXDomain` | `Verdict.Insecure` | `Verdict.Bogus`
   | `Verdict.Indeterminate` (v0.2.0-aligned six-state set; the two
   secure-negative states distinguish proven non-existence from
   "could not classify").
3. `Result.chain` contains each zone's DNSKEY / DS tags and
   algorithms, the key that authenticated its DNSKEY rrset
   (`signedBy`), and one RRSIG verification result per signature
   examined (`signatures`: covered name and type, key tag, algorithm,
   signer, validity window as RFC 3339 strings, and `verified` /
   `expired` / `not-yet-valid` / `unsupported-algorithm` /
   `no-matching-key` / `invalid`); a Bogus chain ends with the step of
   the zone that failed.
4. `Result.insecureAt` / `Result.bogusAt` returns the failure point as
   a string.
4a. `Result.insecureReason` / `Result.bogusReason` explain the failure
    point in a short human-readable string; `Result.negativeReason`
    does the same for `SecureNoData` / `SecureNXDomain` (which NSEC /
    NSEC3 records proved it).
4b. `Result.aliases` lists every CNAME / DNAME hop followed before the
    terminal name, each with the zone that signed it and its own
    verdict; the overall verdict is the worst of the hops (UP-005).
4c. `Result.wildcard` is set when the positive answer was synthesised
    from a wildcard, with the wildcard owner, closest encloser and next
    closer whose non-existence was proven; the verdict stays
    `Verdict.Secure` (UP-006).
4d. `Result.answer` carries the validated RRset and the RRSIGs over it
    that verified, only when the verdict is `Verdict.Secure` (after
    alias hops the terminal RRset; for a wildcard the synthesised one),
    so the caller acts on exactly what was validated (UP-015).
5. `Result.evidence` carries the presentation-form DS / DNSKEY / RRSIG
   data (forwarded into mailsec-probe Signals on the Go path; same
   shape on the TS path).
6. `AbortSignal` propagates cancellation and deadlines (`signal.aborted`
   throws `VerifierChainTimeoutError`; `AbortSignal.timeout(ms)` is the
   recommended deadline source).
7. The trust anchor source is caller-supplied
   (`VerifierOptions.trustAnchors`); the built-in IANA `RootAnchors`
   are the default.
8. DoH providers can be passed as an array (default failover order:
   Cloudflare → Google → Quad9 — see `resolver/doh` package doc for
   the rationale).
9. There is a direct-to-authoritative-NS mode (`resolver/auth`,
   UDP / TCP with TC fallback, to interoperate with mailsec-probe's
   `--dns-server`).
10. `Result` is plain JSON (no `Date`, no `Uint8Array`, no class
    instances) and round-trips through `JSON.stringify` / `JSON.parse`.
11. `Verdict` is a string-valued enum whose string forms are
    `"secure"` / `"secure-nodata"` / `"secure-nxdomain"` / `"insecure"`
    / `"bogus"` / `"indeterminate"` (the four pre-v0.2 strings are
    unchanged so consumers that only know those still work; consumers
    wanting fine-grained negative results route on the dash-separated
    new ones).
12. Errors are typed `Error` subclasses usable with `instanceof`.
    `validate()` rejects only when it cannot classify the query
    (`VerifierConfigError`, `VerifierInvalidQNameError`,
    `VerifierResolverError`, `VerifierChainTimeoutError`,
    `VerifierError`); a Bogus or Insecure verdict is a result, not a
    rejection. Such a result carries a machine-readable
    `Result.reasonCode` (`no-ds`, `ds-mismatch`, `no-dnskey`,
    `trust-anchor-mismatch`, `sig-expired`, `sig-invalid`,
    `unsupported-algorithm`, ...), and `result_error(result)` returns
    the matching subclass (`VerifierNoDSError`,
    `VerifierDSMismatchError`, `VerifierNoDNSKEYError`,
    `VerifierTrustAnchorMismatchError`, `VerifierSigExpiredError`,
    `VerifierSigInvalidError`, `VerifierUnsupportedAlgoError`, ...;
    the Bogus-only ones extend `VerifierBogusError`). The code strings
    and the code → error mapping are the same as the Go side's
    `Result.ReasonCode` / `Result.Err()`. Where the Go side returns
    an Indeterminate `Result` together with an error (an RRSIG whose
    algorithm is unsupported on a path that checks signature octets),
    the TS side rejects with `VerifierUnsupportedAlgoError` and puts
    that `Result` in its `.result`.

### SHOULD

13. A pluggable cache layer (`VerifierOptions.cache`, interface
    `Cache`) so root / TLD DNSKEY rrsets can be reused across a batch
    run. Shipped in v0.4.0 (UP-008) with built-in `MemoryCache`.
14. Streamable verification steps for verbose logging
    (`VerifierOptions.onStep?: (e: StepEvent) => void`, the same event
    kinds as the Go side's `WithStepHandler`); events are delivered
    synchronously and never after `validate()` settles.
15. RR types accepted as `number` (16-bit). Matches the Go side's
    `uint16` and is compatible with `dns-packet`-style ecosystems.
16. Memory efficiency acceptable when validating 100 domains in
    parallel via separate `validate()` calls sharing one `Cache`.

### MAY (future)

17. Helper to convert `Result` records into a `dns-packet`-style
    object form (ecosystem interop).
18. Aggressive negative caching with NSEC / NSEC3 (RFC 8198).
19. RFC 5011 automatic trust anchor updates.

### MUST NOT

20. Call `process.exit`.
21. Produce side effects from importing `@dnsdata/core` that change
    the handler registry. No module registers anything at import
    time. Installing handlers into the default registry is opt-in via
    `registerAllHandlers()` (or `register_dnssec_handlers` /
    `register_legacy_handlers`); as on the Go side,
    `signer.sign_zone` / `signer.build_nsec` install the handlers
    they need when called.
22. Hold module-global state visible across `Verifier` instances.
    Multiple `Verifier`s must be independently configurable and
    independently cancellable. Each `Verifier` has its own RR handler
    `Registry` (`VerifierOptions.registry`; by default one holding
    the DNSSEC handlers), so it works without
    `registerAllHandlers()` and never changes the default registry.
23. Write to the filesystem by default (only touch `~/.dnsdata/` when
    the caller explicitly opts in — the same directory the Go side
    uses).
24. Write to `stdout` / `stderr` (the caller routes output to their
    logger of choice).

MUST NOT 20 (`process.exit`) and 24 (`stdout` / `stderr`) are
contracts of the library modules; the commands under `src/cli/` are
programs, not library code, and are outside their scope.

## 5. Porting policy

Code flows in both directions under the sibling model (see the
[SIBLING.md](docs/SIBLING.md) doc). The rules below cover the
dominant Go → TS port-back case (UP-NNN entries from the Go
`UPSTREAM_FEEDBACK.md`); symmetric rules apply when porting
TS-originated functionality back to Go (UF-NNN entries).

- Port one Go function / file to one TS function / file (no
  opportunistic redesign).
- Go `error` return values become rejected `Promise`s with typed
  `Error` subclasses, never plain `throw`s of strings.
- Go `panic` for unreachable enum cases becomes a typed `Error`
  subclass (`UnknownOpCodeError` etc.); never `throw new RangeError`.
- Go `[]byte` becomes `Uint8Array`. `Buffer` only appears at Node
  `crypto` API boundaries.
- Go `context.Context` becomes `AbortSignal`. `signal.aborted` is
  re-thrown via `check_aborted()` at every chain hop.
- Naming follows TS conventions — `snake_case` for functions and
  module-level identifiers, `PascalCase` for types and classes — even
  though the Go side uses `CamelCase` for both. Public API surface
  (function names, argument order, optionality) stays identical
  modulo case.
- Specs are ported to Jest `describe` / `it` blocks with the same
  inputs and expected outputs as the source.

When you notice a Go-side bug, robustness gap, or API-shape issue
during porting, file a TS-side GitHub issue with the originator tag.
A dedicated TS-side `UPSTREAM_FEEDBACK.md` catalogue is not in this
repo yet — for now, file TS-originated proposals or bug observations
directly as issues (see [`docs/SIBLING.md`](docs/SIBLING.md) §
Origination). New functionality that originates in TS and should be
port-backed to Go is filed against the
[`dnsdata-go`](https://github.com/shigeya/dnsdata-go) repo with a
`UF-NNN` placeholder for that repo's catalogue.

## 6. Roadmap

The version numbers below track parity with the Go sibling. The
[CHANGELOG](./CHANGELOG.md) is the canonical, dated log; this section
captures the high-level milestones.

| Version | Highlight | UP-NNN |
|---|---|---|
| v0.4.0 | First tagged release; full per-package refactor (`types/`, `wire/`, `zone/`, `dnssec/`, `resolver/`, `verifier/`); chain validator; auth resolver; NSEC/NSEC3 negative proofs; CNAME/DNAME chasing; wildcard synthesis; pluggable `Cache` | UP-001..006, UP-008 |
| v0.6.0 | Resolver layer surfaces structured `ResolverResponse` (`records` + `ad` + `rcode`). RCODE classification moves into `verifier/chain.ts:load_records`; NXDOMAIN handled as "no records present" | UP-009 |
| v0.7.0 | RFC 3597 unknown types; strict zone reader and canonical output; zone signer (`signer`); in-memory authority (`memory`) with byte-identical shared vectors; `Result.answer`; RRSIG digest order and validity window fixed (UF-005 / UF-006); `Verifier` exported from the entry point | UP-010..015 |
| v0.8.0 | CD bit on queries; TLSA / SMIMEA / SVCB / HTTPS presented by type; `\DDD` escapes and UTF-8 text for TXT and CAA; NSEC3 signing and NSEC3 proofs from `memory`; `DoTClient`; `parse_message` / `rdata_to_string` exported; received RDATA signed as is (`new_resource_record_with_rdata`); DNAME, alias and wildcard NODATA verdicts fixed | UP-016..019, UF-007 |
| v0.9.0 | `dnsview` diagnostic command (the package's `bin`): one JSON line per query with the verifier `Result` | UP-020 |

Coordinated with mailsec-probe Phase 3.0 (target: mailsec-probe v0.1.0
→ v0.3.0).

Out of scope for the current line (tracked as TODO in `verifier/`):

- Streamable step handler (SHOULD #14).
- RFC 5011 automatic trust-anchor rollover (MAY #19).
- Aggressive negative caching with NSEC / NSEC3 (MAY #18).

The RRSIG validity-window check is in place: the verifier sets its
`now` clock on every `DNSSecZone` it builds (dnsdata-go UF-006).

Per-version detail and PR / issue references live in the
[CHANGELOG](./CHANGELOG.md). Cross-repo origin and feedback log:
[`dnsdata-go/UPSTREAM_FEEDBACK.md`](https://github.com/shigeya/dnsdata-go/blob/main/UPSTREAM_FEEDBACK.md).

Session handoff and ongoing notes live in `CLAUDE.md`.
