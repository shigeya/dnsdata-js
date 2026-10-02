// Public API for @dnsdata/core.
//
// As of P8 (REFACTOR_PLAN.md §3) RR handler registration is opt-in:
// importing this entry point does NOT install anything in the
// handler registry. Consumers must call [registerAllHandlers] once
// at startup (or the per-pkg helpers exported alongside it) before
// ResourceRecord.get_handler() / DNSSecZone signature checks /
// chain validation can resolve the handler for the registered RR
// types. Mirrors dnsdata-go's `dnssec.RegisterHandlers()` and the
// equivalent zone-side initialisation hook.

import { register_dnssec_handlers } from './dnssec/handlers';
import { register_legacy_handlers } from './zone/handlers';

// registerAllHandlers installs the DNSSEC handlers (DNSKEY, CDNSKEY,
// RRSIG, DS, CDS, NSEC, NSEC3, NSEC3PARAM) and the legacy zone
// handlers (TLSA/SMIMEA, SSHFP, SVCB/HTTPS, EUI48/64, HINFO, RP,
// OPENPGPKEY, CERT, LOC, CSYNC, NAPTR, URI). Builtin RR types
// (A, AAAA, NS, PTR, SOA, MX, TXT, SRV, CAA) are encoded inline by
// ResourceRecord and do not need registration.
//
// Idempotent: subsequent calls overwrite the existing factories.
export function registerAllHandlers(): void {
    register_dnssec_handlers();
    register_legacy_handlers();
}

export { register_dnssec_handlers, register_legacy_handlers };

export * from './dns_exception';
export * from './types/dns_type_table';
export * from './types/algorithm';
export * from './wire/dns_wire';
export * from './wire/dns_wire_util';
export { format_generic_rdata, rdata_to_string } from './wire/rdata_decoder';
// The DNS message parser (dnsdata-go wire.ParseMessage, UP-002).
export { parse_message, Header } from './wire/dns_message';
export type { Question, RawRR, RawMessage } from './wire/dns_message';
export * from './zone/dns_zone';
export { parse_generic_rdata } from './zone/generic';
export { compare_canonical_names } from './zone/canonical';
export * from './dnssec/dnssec_key_loader';
export * from './dnssec/dnssec_rr';
export * from './dnssec/dnssec_zone';
export * from './dnssec/root_anchors';
// The zone signer (dnsdata-go `dnssec/signer`, UP-013) as a namespace,
// mirroring the Go package: signer.sign_zone, signer.Key, ...
export * as signer from './dnssec/signer';
export * from './resolver/response';
export * from './resolver/doh';
export * from './resolver/auth';
export * from './resolver/dot';
// The chain validator: the contract of DESIGN.md §3 / §4. The walker's
// internal helpers stay behind the verifier/ barrel.
export * from './verifier/verdict';
export * from './verifier/result';
export * from './verifier/resolver';
export * from './verifier/cache';
export * from './verifier/errors';
export { Verifier, VerifierOptions } from './verifier/verifier';
// The in-memory authority (dnsdata-go `resolver/memory`, UP-014) as a
// namespace, mirroring the Go package: memory.new_authority,
// memory.with_zone, memory.Authority, ...
export * as memory from './resolver/memory';
