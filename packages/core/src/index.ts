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
export * from './zone/dns_zone';
export * from './dnssec/dnssec_key_loader';
export * from './dnssec/dnssec_rr';
export * from './dnssec/dnssec_zone';
export * from './dnssec/root_anchors';
export * from './resolver/doh';
