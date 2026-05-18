// Public API for @dnsdata/core.
//
// Importing this entry point triggers registration of all bundled RR handlers
// (DNSKEY, RRSIG, DS, NSEC/NSEC3, TLSA/SMIMEA, SSHFP, SVCB/HTTPS, EUI48/64,
// HINFO, RP, OPENPGPKEY, CERT, LOC, CSYNC, NAPTR, URI, OPT) via dnssec_zone.

export * from './lib/dns_exception';
export * from './types/dns_type_table';
export * from './types/algorithm';
export * from './wire/dns_wire';
export * from './wire/dns_wire_util';
export * from './zone/dns_zone';
export * from './dnssec/dnssec_key_loader';
export * from './dnssec/dnssec_rr';
export * from './dnssec/dnssec_zone';
export * from './dnssec/root_anchors';
export * from './lib/resolver/doh';
