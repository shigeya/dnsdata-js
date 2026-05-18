// Back-compat re-export shim. The DNSSEC handlers now live in their
// own per-RR files under dnssec/ to mirror dnsdata-go:
//
//   - dnskey.ts  ← DNSKey + RSA/ECDSA/EdDSA loaders
//   - rrsig.ts   ← RRSig
//   - ds.ts      ← DNSRR_DS
//   - nsec.ts    ← DNSRR_NSEC (+ type-bitmap encode/decode statics)
//   - nsec3.ts   ← DNSRR_NSEC3, DNSRR_NSEC3PARAM, owner_hash_from_name
//   - handlers.ts ← register_rr_handler(...) side effects
//
// External callers and tests can keep importing
// '@dnsdata/core' or '.../dnssec/dnssec_rr' — both surfaces continue
// to expose the same symbols. The side-effect import below ensures
// the RR-handler registry is populated whenever this module loads,
// matching the pre-split behaviour.

import './handlers';

export { DNSKey } from './dnskey';
export { RRSig } from './rrsig';
export { DNSRR_DS } from './ds';
export { DNSRR_NSEC } from './nsec';
export { DNSRR_NSEC3, DNSRR_NSEC3PARAM, owner_hash_from_name } from './nsec3';
