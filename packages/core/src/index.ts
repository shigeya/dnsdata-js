// Public API for @dnsdata/core.
//
// Importing this entry point triggers registration of all bundled RR handlers
// (DNSKEY, RRSIG, DS, NSEC/NSEC3, TLSA/SMIMEA, SSHFP, SVCB/HTTPS, EUI48/64,
// HINFO, RP, OPENPGPKEY, CERT, LOC, CSYNC, NAPTR, URI, OPT) via dnssec_zone.

export * from './lib/dns_exception';
export * from './lib/dns_type_table';
export * from './lib/dns_wire';
export * from './lib/dns_wire_util';
export * from './lib/dns_zone';
export * from './lib/dnssec_key_loader';
export * from './lib/dnssec_rr';
export * from './lib/dnssec_zone';
export * from './lib/root_anchors';
