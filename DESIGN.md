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
| `zone/` | Zone-file parser, `ResourceRecord`, pluggable RR-type handler registry, legacy RR set under `zone/rr/` | `zone/` |
| `dnssec/` | `DNSKey` / `RRSig` / `DNSRR_DS` / `DNSRR_NSEC` / `DNSRR_NSEC3` handlers, `DNSSecZone`, root trust anchors, canonical-name helpers | `dnssec/` |
| `resolver/doh/` | RFC 8484 DoH client with Cloudflare / Google / Quad9 sequential failover | `resolver/doh/` |
| `resolver/auth/` | UDP + TCP authoritative-DNS client with TC-fallback and multi-server failover | `resolver/auth/` |
| `verifier/` | DNSSEC chain-of-trust walker (`Verifier.validate(qname, qtype, signal?) → Promise<Result>`) | `verifier/` |
| `cli/` | Reference CLI (`cli/main.ts`); not part of the library public API | (no Go counterpart) |

The exported public surface lives in `packages/core/src/index.ts` and
its barrel re-exports. RR handler installation is **opt-in**: importing
the entry point does NOT register anything. Callers invoke
`registerAllHandlers()` (or the per-package `register_dnssec_handlers`
/ `register_legacy_handlers` helpers) once at startup before
`DNSSecZone` signature checks or `Verifier.validate()` run.

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
    now?: () => Date;                       // RRSIG window source (reserved)
    cache?: Cache;                          // pluggable cache (UP-008)
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
    aliases?: AliasStep[];                  // CNAME / DNAME hops (UP-005)
    wildcard?: WildcardInfo;                // wildcard synthesis (UP-006)
    evidence: Evidence;                     // presentation-form raw data
}
```

The detailed contract is in §4 (Requirements).

## 4. Requirements (mirror of mailsec-probe `DESIGN.md §16`)

The API contract that mailsec-probe (= the consumer) asks the dnsdata
implementations to honor. The same text lives in mailsec-probe's
DESIGN.md and is mirrored on the Go side at
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
3. `Result.chain` contains each zone's DNSKEY / DS tags, algorithms,
   and the RRSIG verification trail.
4. `Result.insecureAt` / `Result.bogusAt` returns the failure point as
   a string.
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
12. Errors are typed `Error` subclasses usable with `instanceof`:
    `VerifierConfigError`, `VerifierInvalidQNameError`,
    `VerifierResolverError`, `VerifierChainTimeoutError`,
    `VerifierTrustAnchorMismatchError`. The Go side exposes
    `errors.Is`-friendly sentinels; the TS side exposes class
    discrimination. Category meanings stay in sync.

### SHOULD

13. A pluggable cache layer (`VerifierOptions.cache`, interface
    `Cache`) so root / TLD DNSKEY rrsets can be reused across a batch
    run. Shipped in v0.4.0 (UP-008) with built-in `MemoryCache`.
14. Streamable verification steps for verbose logging. The TS side
    does not yet expose a `StepHandler` — tracked as a future
    enhancement.
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
    the handler registry. RR handler installation is opt-in via
    `registerAllHandlers()`. (Per-handler-module imports such as
    `import './dnssec/dnssec_rr'` still register at import time as a
    TS-specific implementation detail of those files; the public
    entry point does not pull them transitively. Documented in
    [`docs/SIBLING.md`](docs/SIBLING.md) §TS-specific surface.)
22. Hold module-global state visible across `Verifier` instances.
    Multiple `Verifier`s must be independently configurable and
    independently cancellable.
23. Write to the filesystem by default (only touch `~/.dnsdata/` when
    the caller explicitly opts in — shared with the Go side's
    `~/.dnsdata-go/`).
24. Write to `stdout` / `stderr` (the caller routes output to their
    logger of choice).

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

Coordinated with mailsec-probe Phase 3.0 (target: mailsec-probe v0.1.0
→ v0.3.0).

Out of scope for the current line (tracked as TODO in `verifier/`):

- Streamable step handler (SHOULD #14).
- RFC 5011 automatic trust-anchor rollover (MAY #19).
- Aggressive negative caching with NSEC / NSEC3 (MAY #18).
- RRSIG validity-window check (the `now` option in `VerifierOptions`
  is reserved for this).

Per-version detail and PR / issue references live in the
[CHANGELOG](./CHANGELOG.md). Cross-repo origin and feedback log:
[`dnsdata-go/UPSTREAM_FEEDBACK.md`](https://github.com/shigeya/dnsdata-go/blob/main/UPSTREAM_FEEDBACK.md).

Session handoff and ongoing notes live in `CLAUDE.md`.
