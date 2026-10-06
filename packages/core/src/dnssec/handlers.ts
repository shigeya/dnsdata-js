// Opt-in registration of the DNSSEC RR handlers with the zone's
// handler factory. Mirrors dnsdata-go's `dnssec.RegisterHandlers()`
// in shape: there are no module-load side effects, so a consumer
// that imports nothing from this file (or transitively from any
// dnssec/* file) keeps the handler registry empty.
//
// Idempotent: callers may invoke this more than once. The registry
// overwrites the existing factory each call.
//
// REFACTOR_PLAN.md §3 P8: opt-in handler registration.

import { StringToRRType } from '../types/dns_type_table';
import { Registry, default_registry } from '../zone/registry';
import { DNSKey } from './dnskey';
import { RRSig } from './rrsig';
import { DNSRR_DS } from './ds';
import { DNSRR_NSEC } from './nsec';
import { DNSRR_NSEC3, DNSRR_NSEC3PARAM } from './nsec3';

// register_dnssec_handlers installs the DNSSEC handlers into the
// default registry ([default_registry]).
export function register_dnssec_handlers(): void {
    register_dnssec_handlers_into(default_registry());
}

// register_dnssec_handlers_into installs the DNSSEC handlers (DNSKEY,
// CDNSKEY, RRSIG, DS, CDS, NSEC, NSEC3, NSEC3PARAM; the set
// register_dnssec_handlers installs) into registry, leaving the default
// registry untouched. Pair it with DNSSecZone.set_registry or
// VerifierOptions.registry. Ports dnsdata-go `dnssec.RegisterHandlersInto`.
export function register_dnssec_handlers_into(registry: Registry): void {
    registry.register(StringToRRType('DNSKEY'), (rr, value) => new DNSKey(rr, value));
    // RFC 7344 §3.2: CDNSKEY wire and presentation format is identical to
    // DNSKEY (RFC 4034). The DNSKey handler class is reused; only the RR
    // type code (60) differs.
    registry.register(StringToRRType('CDNSKEY'), (rr, value) => new DNSKey(rr, value));
    registry.register(StringToRRType('RRSIG'), (rr, value) => new RRSig(rr, value));
    registry.register(StringToRRType('DS'), (rr, value) => new DNSRR_DS(rr, value));
    // RFC 7344 §3.1: CDS wire and presentation format is identical to DS
    // (RFC 4034). The DNSRR_DS handler class is reused; only the RR type
    // code (59) differs.
    registry.register(StringToRRType('CDS'), (rr, value) => new DNSRR_DS(rr, value));
    registry.register(StringToRRType('NSEC'), (rr, value) => new DNSRR_NSEC(rr, value));
    registry.register(StringToRRType('NSEC3'), (rr, value) => new DNSRR_NSEC3(rr, value));
    registry.register(StringToRRType('NSEC3PARAM'), (rr, value) => new DNSRR_NSEC3PARAM(rr, value));
}
