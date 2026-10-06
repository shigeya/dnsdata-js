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
import { Registry, default_registry } from './registry';
import { DNSRR_TLSA, DNSRR_SMIMEA } from './rr/dane_rr';
import { DNSRR_SSHFP } from './rr/sshfp_rr';
import { DNSRR_SVCB, svcb_from_rdata } from './rr/svcb_rr';
import { DNSRR_EUI } from './rr/eui_rr';
import { DNSRR_HINFO } from './rr/hinfo_rr';
import { DNSRR_RP } from './rr/rp_rr';
import { DNSRR_OPENPGPKEY } from './rr/openpgpkey_rr';
import { DNSRR_CERT } from './rr/cert_rr';
import { DNSRR_LOC } from './rr/loc_rr';
import { DNSRR_CSYNC } from './rr/csync_rr';
import { DNSRR_NAPTR } from './rr/naptr_rr';
import { DNSRR_URI } from './rr/uri_rr';

// register_legacy_handlers installs the zone handlers into the default
// registry ([default_registry]).
export function register_legacy_handlers(): void {
    register_legacy_handlers_into(default_registry());
}

// register_legacy_handlers_into installs the zone handlers (the set
// register_legacy_handlers installs) into registry, leaving the default
// registry untouched. Ports dnsdata-go `zone.RegisterHandlersInto`.
export function register_legacy_handlers_into(registry: Registry): void {
    registry.register(StringToRRType('TLSA'), (rr, value) => new DNSRR_TLSA(rr, value));
    registry.register(StringToRRType('SMIMEA'), (rr, value) => new DNSRR_SMIMEA(rr, value));
    registry.register(StringToRRType('SSHFP'), (rr, value) => new DNSRR_SSHFP(rr, value));
    // RFC 9460 §9: HTTPS shares wire/presentation format with SVCB.
    // RFC 3597 generic values are decoded from their octets directly.
    registry.register(StringToRRType('SVCB'),  (rr, value) => new DNSRR_SVCB(rr, value), svcb_from_rdata);
    registry.register(StringToRRType('HTTPS'), (rr, value) => new DNSRR_SVCB(rr, value), svcb_from_rdata);
    registry.register(StringToRRType('EUI48'), (rr, value) => new DNSRR_EUI(rr, value, 6));
    registry.register(StringToRRType('EUI64'), (rr, value) => new DNSRR_EUI(rr, value, 8));
    registry.register(StringToRRType('HINFO'), (rr, value) => new DNSRR_HINFO(rr, value));
    registry.register(StringToRRType('RP'),    (rr, value) => new DNSRR_RP(rr, value));
    registry.register(StringToRRType('OPENPGPKEY'), (rr, value) => new DNSRR_OPENPGPKEY(rr, value));
    registry.register(StringToRRType('CERT'),  (rr, value) => new DNSRR_CERT(rr, value));
    registry.register(StringToRRType('LOC'),   (rr, value) => new DNSRR_LOC(rr, value));
    registry.register(StringToRRType('CSYNC'), (rr, value) => new DNSRR_CSYNC(rr, value));
    registry.register(StringToRRType('NAPTR'), (rr, value) => new DNSRR_NAPTR(rr, value));
    registry.register(StringToRRType('URI'),   (rr, value) => new DNSRR_URI(rr, value));
}
