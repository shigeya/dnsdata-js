# CLAUDE.md — dnsdata-js

Operating notes for working in this repository with Claude Code.

## Lineage

```
wide-cpp-lib (C++) → dnsdata-js (TypeScript)   ← here
                          ⇅
                     dnsdata-go (Go)
```

- Sibling implementation:
  [`shigeya/dnsdata-go`](https://github.com/shigeya/dnsdata-go) —
  maintained as an equal sibling, not as a downstream port. See
  [`docs/SIBLING.md`](docs/SIBLING.md) for originator tags, drift
  policy, and cross-repo module mapping.
- Primary consumer:
  [`shigeya/mailsec-probe`](https://github.com/shigeya/mailsec-probe)
  (consumes the Go sibling directly; the TS contract stays in lockstep
  via [`DESIGN.md §4`](DESIGN.md)).

## Design rules

- **Pure port / pure TypeScript.** No `dns-packet`, no `node-forge`,
  no `tweetnacl`. Crypto comes from Node's built-in `crypto`; wire
  format and zone parsing are hand-rolled in this repo.
- The public API must satisfy the MUST / SHOULD / MAY / MUST NOT
  clauses in mailsec-probe `DESIGN.md §16`. Those clauses are mirrored
  in [`DESIGN.md §4`](DESIGN.md) as the source of truth for the TS
  contract (idiom-translated from the Go side).
- Public API shape:
  - `Verifier.validate(qname, qtype, signal?) → Promise<Result>` —
    chain validation
  - `DoHClient` / `AuthClient` — DoH and direct-to-authoritative DNS
  - `dnssec/*` — DNSKEY / RRSIG / DS / NSEC / NSEC3 primitives
  - `wire/*`, `types/*` — lower-level primitives
- Handler registration is **opt-in** at the public entry point. Callers
  invoke `registerAllHandlers()` once at startup; importing
  `@dnsdata/core` does not install anything (mirrors the Go side's
  explicit `RegisterHandlers()` call).
- Never call `process.exit`. Never write to `stdout` / `stderr` from
  library code. Never hold module-global state visible across `Verifier`
  instances — multiple `Verifier`s must be usable concurrently and
  independently.
- All wire format / binary data uses `Uint8Array`. `Buffer` only appears
  at Node `crypto` API boundaries.

## Porting workflow (recommended)

When porting a new Go module / file to TypeScript (the dominant
direction since v0.4.0):

1. Read the Go source (`dnsdata-go/<pkg>/<x>.go`) and its test
   (`<x>_test.go`).
2. Locate the matching TS file via `docs/SIBLING.md` § Cross-repo
   module mapping. The layout is intentionally 1-to-1.
3. Port the function while applying the idiom mapping:
   - `error` returns → rejected `Promise` with a typed `Error`
     subclass.
   - Sentinel `var Err…` → `class extends Error` (matching category).
   - `[]byte` → `Uint8Array`.
   - `context.Context` → `AbortSignal`; re-check via
     `check_aborted(signal)` at every chain hop.
   - `CamelCase` → `snake_case` for functions / module-level
     identifiers; `PascalCase` for types and classes.
4. Port the table-driven `t.Run` test to Jest `describe` / `it`
   blocks with identical inputs / expected outputs.
5. Confirm parity with `cd packages/core && npx jest <pattern>`.
6. Run `cd packages/core && npx tsc --noEmit && npx eslint src/ tests/`.

Where the Go source returns a typed error for an unknown enum value,
the TS equivalent throws a typed `Error` subclass (e.g.
`UnknownOpCodeError`), never a bare `RangeError`.

If you spot a Go-side bug, robustness gap, or API-shape issue during
porting, and you change behaviour on the TS side as a result, file an
issue on this repo with the *Originated in dnsdata-go vX.Y.Z* tag and
cross-reference the Go-side `UP-NNN` from
[`dnsdata-go/UPSTREAM_FEEDBACK.md`](https://github.com/shigeya/dnsdata-go/blob/main/UPSTREAM_FEEDBACK.md).

For new functionality that originates in TS and should be port-backed
to Go, file a `UF-NNN` placeholder issue on the Go repo. A dedicated
TS-side `UPSTREAM_FEEDBACK.md` catalogue is not maintained in this repo;
GitHub Issues with the originator tag fill that role.

## Work in progress

See the "Roadmap" section of [`DESIGN.md`](DESIGN.md). Progress is
synchronised with `mailsec-probe` Phase 3.0 and tracks the
`dnsdata-go` sibling's version numbers — current line is v0.6.0.

## Testing

- Base layer: `cd packages/core && npx jest`.
- DNSSEC primitives use Known-Answer Tests under
  `packages/core/tests/`.
- Target ≥ 80% line coverage (matches the Go side's bar).
- Tests are organised by package mirroring the source layout
  (`tests/{types,wire,zone,dnssec,resolver,verifier}/`); the CLI in
  `src/cli/` currently has no dedicated test directory.

## Commits

- Conventional Commits (`feat:`, `fix:`, `refactor:`, `docs:`,
  `test:`, …).
- Auto-signatures such as `Co-Authored-By` are disabled globally in
  `~/.claude/settings.json`.
