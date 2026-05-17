# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

dnsdata-js is a DNS/DNSSEC protocol implementation library in TypeScript, ported from a C++ reference library (wide-cpp-lib). It is structured as a Lerna monorepo with a single package: `@dnsdata/core` (located in `packages/core/`). A sibling Go implementation lives in `dnsdata-go`; the `~/.dnsdata/` user-data location is intentionally shared between the two.

## Build & Test Commands

All commands below run from `packages/core/`:

```bash
# Install dependencies (run from repo root)
npm install && cd packages/core && npm install

# Run all tests
cd packages/core && npx jest

# Run a single test file
cd packages/core && npx jest tests/lib/dns_wire.spec.ts

# Compile TypeScript (no build script defined; use tsc directly)
cd packages/core && npx tsc

# Lint
cd packages/core && npx eslint src/ tests/
```

The only defined npm script in the package is `test` → `jest`.

## Architecture

### Package: `@dnsdata/core` (`packages/core/`)

Source lives in `src/lib/`, tests in `tests/lib/` (pattern: `*.spec.ts`).

#### Core DNS modules

- **`dns_wire.ts`** — Domain name wire format encoding/decoding. Uses `Uint8Array` for binary data.
- **`dns_wire_util.ts`** — `WireBuilder` class for constructing binary buffers (big-endian uint8/16/32, byte append). Also provides `compare_uint8arrays` for canonical ordering.
- **`dns_type_table.ts`** — Bidirectional conversion between DNS numeric codes and string names (OpCodes, RCodes, RR Types, RR Classes). Includes `QTypeValidForRequest` and `QClassValidForRequest`. Throws `RangeError` on unknown input.
- **`dns_exception.ts`** — Exception hierarchy using `ts-custom-error`: `DNSZoneException`, `DNSZonePresentationFormatError`, `DNSZoneRDataFormatError`.

#### Zone management

- **`dns_zone.ts`** — `ResourceRecord` class (stores label, TTL, class, type, value text), `ResourceRecordHandler` abstract base, and `Zone` class (record store with zone file parser). Supports per-type wire format builders for A, AAAA, NS, PTR, SOA, MX, TXT, SRV, CAA. Uses a handler registry pattern (`register_rr_handler`) for extensible RR type handling. Zone parser supports `$ORIGIN` and `$TTL` directives.
- **`dnssec_zone.ts`** — `DNSSecZone` extends `Zone` with DNSSEC operations: `find_rrsigs`, `find_dnskey`, `create_digest_target` (RFC4034 Section 6.2), `verify_rrsig`, `verify_rrset`, `verify_ksk/zsk`, `verify_delegation_signer`, and `sign_rr`.

#### DNSSEC record handlers

- **`dnssec_rr.ts`** — `DNSKey` (DNSKEY parsing, key tag computation per RFC4034 Appendix B, RSA/ECDSA/Ed25519 public key loading, sign/verify via Node.js crypto), `RRSig` (RRSIG parsing, RDATA digest target construction), `DNSRR_DS` (DS parsing, digest verification with SHA-1/SHA-256/SHA-384), `DNSRR_NSEC` (NSEC parsing, type bitmap encode/decode), `DNSRR_NSEC3` (NSEC3 parsing, hash computation). These register themselves into the handler registry on module load.
- **`dnssec_key_loader.ts`** — Loads private keys from ISC/BIND keygen file format: RSA (JWK), ECDSA P-256/P-384 (PKCS#8 DER), Ed25519/Ed448 (PKCS#8 DER).

### Key Design Patterns

- **Binary data**: All wire format uses `Uint8Array` (not JS strings)
- **Crypto**: Node.js `crypto` module (no external crypto libs). Algorithm mapping: DNSSEC algo 5/7→sha1, 8→sha256, 10→sha512, 13→ECDSA P-256/sha256, 14→ECDSA P-384/sha384, 15→Ed25519, 16→Ed448
- **Handler registry**: `dns_zone.ts` provides `register_rr_handler()`, `dnssec_rr.ts` registers DNSKEY/RRSIG/DS/NSEC/NSEC3 handlers at module load time. This avoids circular imports.
- **Zone file parser**: Handles comments (`;`), continuation lines `()`, implicit labels (leading whitespace), `$ORIGIN`, `$TTL`, and both explicit/implicit class formats.
- **RRSIG verification**: Uses any-valid semantics per RFC 4035 Section 5.3.3 (at least one valid RRSIG suffices).

### Conventions

- TypeScript strict mode, target ES2017, CommonJS modules
- `Uint8Array` for all binary/wire format data, `Buffer` only at crypto API boundaries
- Jest with ts-jest preset; test files in `tests/lib/` use `describe`/`it` blocks
- Type aliases `ns_type`, `ns_class` follow BIND naming convention
