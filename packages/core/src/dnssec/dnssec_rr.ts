// Back-compat re-export shim. The DNSSEC handlers now live in their
// own per-RR files under dnssec/ to mirror dnsdata-go:
//
//   - dnskey.ts  ← DNSKey + RSA/ECDSA/EdDSA loaders
//   - rrsig.ts   ← RRSig
//   - ds.ts      ← DNSRR_DS
//   - nsec.ts    ← DNSRR_NSEC (+ type-bitmap encode/decode statics)
//   - nsec3.ts   ← DNSRR_NSEC3, DNSRR_NSEC3PARAM, owner_hash_from_name
//   - handlers.ts ← register_dnssec_handlers() (opt-in)
//
// External callers and tests can keep importing
// '@dnsdata/core' or '.../dnssec/dnssec_rr' — both surfaces continue
// to expose the same symbols.
//
// As of P8 there is no module-load side effect: consumers must call
// registerAllHandlers() (or register_dnssec_handlers() if they only
// want the DNSSEC surface) before the handler registry is populated.
// See src/index.ts for the public entry point.

export { DNSKey } from './dnskey';
export { RRSig } from './rrsig';
export { DNSRR_DS } from './ds';
export { DNSRR_NSEC } from './nsec';
export { DNSRR_NSEC3, DNSRR_NSEC3PARAM, owner_hash_from_name } from './nsec3';
export { register_dnssec_handlers } from './handlers';
