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
import { register_rr_handler } from '../zone/dns_zone';
import { DNSKey } from './dnskey';
import { RRSig } from './rrsig';
import { DNSRR_DS } from './ds';
import { DNSRR_NSEC } from './nsec';
import { DNSRR_NSEC3, DNSRR_NSEC3PARAM } from './nsec3';

export function register_dnssec_handlers(): void {
    register_rr_handler(StringToRRType('DNSKEY'), (rr, value) => new DNSKey(rr, value));
    // RFC 7344 §3.2: CDNSKEY wire and presentation format is identical to
    // DNSKEY (RFC 4034). The DNSKey handler class is reused; only the RR
    // type code (60) differs.
    register_rr_handler(StringToRRType('CDNSKEY'), (rr, value) => new DNSKey(rr, value));
    register_rr_handler(StringToRRType('RRSIG'), (rr, value) => new RRSig(rr, value));
    register_rr_handler(StringToRRType('DS'), (rr, value) => new DNSRR_DS(rr, value));
    // RFC 7344 §3.1: CDS wire and presentation format is identical to DS
    // (RFC 4034). The DNSRR_DS handler class is reused; only the RR type
    // code (59) differs.
    register_rr_handler(StringToRRType('CDS'), (rr, value) => new DNSRR_DS(rr, value));
    register_rr_handler(StringToRRType('NSEC'), (rr, value) => new DNSRR_NSEC(rr, value));
    register_rr_handler(StringToRRType('NSEC3'), (rr, value) => new DNSRR_NSEC3(rr, value));
    register_rr_handler(StringToRRType('NSEC3PARAM'), (rr, value) => new DNSRR_NSEC3PARAM(rr, value));
}
