// Side-effect module: registers the DNSSEC RR handlers with the
// zone's handler factory. Imported by dnssec_rr.ts (back-compat
// barrel) and by dnssec_zone.ts so that callers loading either entry
// point pick up the registrations.
//
// Ports dnsdata-go `dnssec/handlers.go`.

import { StringToRRType } from '../types/dns_type_table';
import { register_rr_handler } from '../zone/dns_zone';
import { DNSKey } from './dnskey';
import { RRSig } from './rrsig';
import { DNSRR_DS } from './ds';
import { DNSRR_NSEC } from './nsec';
import { DNSRR_NSEC3, DNSRR_NSEC3PARAM } from './nsec3';

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
