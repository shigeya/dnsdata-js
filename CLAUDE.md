# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

dnsjs is a DNS/DNSSEC protocol implementation library in TypeScript, ported from a C++ reference library (wide-cpp-lib). It is structured as a Lerna monorepo with a single package: `@dnsjs/dns` (located in `packages/dns-data/`).

## Build & Test Commands

All commands below run from `packages/dns-data/`:

```bash
# Install dependencies (run from repo root)
npm install && cd packages/dns-data && npm install

# Run all tests
cd packages/dns-data && npx jest

# Run a single test file
cd packages/dns-data && npx jest tests/lib/dns_wire.spec.ts

# Compile TypeScript (no build script defined; use tsc directly)
cd packages/dns-data && npx tsc

# Lint
cd packages/dns-data && npx eslint src/ tests/
```

The only defined npm script in the package is `test` → `jest`.

## Architecture

### Package: `@dnsjs/dns` (`packages/dns-data/`)

Source lives in `src/lib/`, tests in `tests/lib/` (pattern: `*.spec.ts`).

#### Core DNS modules

- **`dns_wire.ts`** — Domain name wire format encoding/decoding. Uses `Uint8Array` for binary data.
- **`dns_wire_util.ts`** — `WireBuilder` class for constructing binary buffers (big-endian uint8/16/32, byte append). Also provides `compare_uint8arrays` for canonical ordering.
- **`dns_type_table.ts`** — Bidirectional conversion between DNS numeric codes and string names (OpCodes, RCodes, RR Types, RR Classes). Includes `QTypeValidForRequest` and `QClassValidForRequest`. Throws `RangeError` on unknown input.
- **`dns_exception.ts`** — Exception hierarchy using `ts-custom-error`: `DNSZoneException`, `DNSZonePresentationFormatError`, `DNSZoneRDataFormatError`.

#### Zone management

- **`dns_zone.ts`** — `ResourceRecord` class (stores label, TTL, class, type, value text), `ResourceRecordHandler` abstract base, and `Zone` class (record store with zone file parser). Supports per-type wire format builders for A, AAAA, NS, PTR, SOA. Uses a handler registry pattern (`register_rr_handler`) for extensible RR type handling.
- **`dnssec_zone.ts`** — `DNSSecZone` extends `Zone` with DNSSEC operations: `find_rrsigs`, `find_dnskey`, `create_digest_target` (RFC4034 Section 6.2), `verify_rrsig`, `verify_rrset`, `verify_ksk/zsk`, `verify_delegation_signer`, and `sign_rr`.

#### DNSSEC record handlers

- **`dnssec_rr.ts`** — `DNSKey` (DNSKEY parsing, key tag computation per RFC4034 Appendix B, RSA public key loading from RFC3110, sign/verify via Node.js crypto), `RRSig` (RRSIG parsing, RDATA digest target construction), `DNSRR_DS` (DS parsing, digest verification). These register themselves into the handler registry on module load.
- **`dnssec_key_loader.ts`** — Loads RSA private keys from ISC/BIND keygen file format (key=value pairs with base64-encoded components → JWK → `crypto.createPrivateKey`).

### Key Design Patterns

- **Binary data**: All wire format uses `Uint8Array` (not JS strings)
- **Crypto**: Node.js `crypto` module (no external crypto libs). Algorithm mapping: DNSSEC algo 5/7→sha1, 8→sha256, 10→sha512
- **Handler registry**: `dns_zone.ts` provides `register_rr_handler()`, `dnssec_rr.ts` registers DNSKEY/RRSIG/DS handlers at module load time. This avoids circular imports.
- **Zone file parser**: Handles comments (`;`), continuation lines `()`, implicit labels (leading whitespace), and both explicit/implicit class formats.

### Conventions

- TypeScript strict mode, target ES2017, CommonJS modules
- `Uint8Array` for all binary/wire format data, `Buffer` only at crypto API boundaries
- Jest with ts-jest preset; test files in `tests/lib/` use `describe`/`it` blocks
- Type aliases `ns_type`, `ns_class` follow BIND naming convention
