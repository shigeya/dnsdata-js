// Opt-in registration of the legacy RR-type handlers under
// zone/rr/. Mirrors the dnsdata-go side's planned handler bundle for
// these record types (see UPSTREAM_FEEDBACK.md UF-005..UF-017
// roadmap). Calling register_legacy_handlers() installs all 16
// (type, factory) pairs in a single batch; not calling it leaves
// these RR types unregistered so ResourceRecord.get_handler() returns
// undefined for them.
//
// Idempotent: subsequent calls just overwrite the factories. The
// zone module's builtin types (A, AAAA, NS, PTR, SOA, MX, TXT, SRV,
// CAA) are encoded inline by ResourceRecord and do NOT go through
// register_rr_handler, so they need no opt-in.
//
// REFACTOR_PLAN.md §3 P8: opt-in handler registration.

import { StringToRRType } from '../types/dns_type_table';
import { register_rr_handler } from './dns_zone';
import { DNSRR_TLSA, DNSRR_SMIMEA } from './rr/dane_rr';
import { DNSRR_SSHFP } from './rr/sshfp_rr';
import { DNSRR_SVCB } from './rr/svcb_rr';
import { DNSRR_EUI } from './rr/eui_rr';
import { DNSRR_HINFO } from './rr/hinfo_rr';
import { DNSRR_RP } from './rr/rp_rr';
import { DNSRR_OPENPGPKEY } from './rr/openpgpkey_rr';
import { DNSRR_CERT } from './rr/cert_rr';
import { DNSRR_LOC } from './rr/loc_rr';
import { DNSRR_CSYNC } from './rr/csync_rr';
import { DNSRR_NAPTR } from './rr/naptr_rr';
import { DNSRR_URI } from './rr/uri_rr';

export function register_legacy_handlers(): void {
    register_rr_handler(StringToRRType('TLSA'), (rr, value) => new DNSRR_TLSA(rr, value));
    register_rr_handler(StringToRRType('SMIMEA'), (rr, value) => new DNSRR_SMIMEA(rr, value));
    register_rr_handler(StringToRRType('SSHFP'), (rr, value) => new DNSRR_SSHFP(rr, value));
    // RFC 9460 §9: HTTPS shares wire/presentation format with SVCB.
    register_rr_handler(StringToRRType('SVCB'),  (rr, value) => new DNSRR_SVCB(rr, value));
    register_rr_handler(StringToRRType('HTTPS'), (rr, value) => new DNSRR_SVCB(rr, value));
    register_rr_handler(StringToRRType('EUI48'), (rr, value) => new DNSRR_EUI(rr, value, 6));
    register_rr_handler(StringToRRType('EUI64'), (rr, value) => new DNSRR_EUI(rr, value, 8));
    register_rr_handler(StringToRRType('HINFO'), (rr, value) => new DNSRR_HINFO(rr, value));
    register_rr_handler(StringToRRType('RP'),    (rr, value) => new DNSRR_RP(rr, value));
    register_rr_handler(StringToRRType('OPENPGPKEY'), (rr, value) => new DNSRR_OPENPGPKEY(rr, value));
    register_rr_handler(StringToRRType('CERT'),  (rr, value) => new DNSRR_CERT(rr, value));
    register_rr_handler(StringToRRType('LOC'),   (rr, value) => new DNSRR_LOC(rr, value));
    register_rr_handler(StringToRRType('CSYNC'), (rr, value) => new DNSRR_CSYNC(rr, value));
    register_rr_handler(StringToRRType('NAPTR'), (rr, value) => new DNSRR_NAPTR(rr, value));
    register_rr_handler(StringToRRType('URI'),   (rr, value) => new DNSRR_URI(rr, value));
}
