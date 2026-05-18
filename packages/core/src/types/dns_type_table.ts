// Type Table

import {
    UnknownOpCodeError,
    UnknownRCodeError,
    UnknownRRTypeError,
    UnknownRRClassError,
} from '../dns_exception';

type ns_opcode = number;
type ns_rcode = number;
type ns_type = number;
type ns_class = number;

export function OpCodeToString(opcode: ns_opcode) : string {
    switch (opcode) {
        case 0 /* ns_o_query */  :	return "Query";	 // Standard query.
        case 1 /* ns_o_iquery */ : 	return "IQuery"; // Inverse query (deprecated/unsupported).
        case 2 /* ns_o_status */ :	return "Status"; // Name server status query (unsupported).
        /* Opcode 3 is undefined/reserved. */
        case 4 /* ns_o_notify */ :	return "Notify"; // Zone change notification.
        case 5 /* ns_o_update */ :	return "Update"; // Zone update message.

        default:
            throw new UnknownOpCodeError(opcode, `OpCodeToString: unknown ns_opcode <${opcode}>`);
    }
}
export function StringToOpCode(str: string) : ns_opcode {
    switch (str) {
        case "Query" /* ns_o_query */  :	return 0;	 // Standard query.
        case "IQuery" /* ns_o_iquery */ : 	return 1; // Inverse query (deprecated/unsupported).
        case "Status" /* ns_o_status */ :	return 2; // Name server status query (unsupported).
        /* Opcode 3 is undefined/reserved. */
        case "Notify" /* ns_o_notify */ :	return 4; // Zone change notification.
        case "Update" /* ns_o_update */ :	return 5; // Zone update message.

        default:
            throw new UnknownOpCodeError(str, `StringToOpCode: unknown opcode name "${str}"`);
    }
}


export function RCodeToString(rcode: ns_rcode) : string {
    switch (rcode) {
    case 0 /* ns_r_noerror */: return "NOERROR";	// No error occurred. 
    case 1 /* ns_r_formerr */: return "FORMERR";	// Format error. 
    case 2 /* ns_r_servfail */: return "SERVFAIL";	// Server failure. 
    case 3 /* ns_r_nxdomain */: return "NXDOMAIN";	// Name error. 
    case 4 /* ns_r_notimpl */: return "NOTIMPL";	// Unimplemented. 
    case 5 /* ns_r_refused */: return "REFUSED";	// Operation refused. 
	/* these are for BIND_UPDATE */
    case 6 /* ns_r_yxdomain */: return "YXDOMAIN";	// Name exists 
    case 7 /* ns_r_yxrrset */: return "YXRRSET";	// RRset exists 
    case 8 /* ns_r_nxrrset */: return "NXRRSET";	// RRset does not exist 
    case 9 /* ns_r_notauth */: return "NOTAUTH";	// Not authoritative for zone 
    case 10 /* ns_r_notzone */: return "NOTZONE";	// Zone of record different from zone section 
    // ns_r_max = 11
    // The following are TSIG errors */
    case 16 /* ns_r_badvers */:	return "BADVERS/SIG";
	// The following are EDNS extended rcodes */
    // TODO: case /* ns_r_badsig */:	return "BADSIG"; // == badvers */
    case 17 /* ns_r_badkey */:	return "BADKEY";
    case 18 /* ns_r_badtime */:	return "BADTIME";

    default:
        throw new UnknownRCodeError(rcode, `RCodeToString: unknown ns_rcode <${rcode}>`);
    }
}

export function StringToRCode(str: string) : ns_rcode {
    switch (str) {
    case "NOERROR" /* ns_r_noerror */: return 0;	// No error occurred. 
    case "FORMERR" /* ns_r_formerr */: return 1;	// Format error. 
    case "SERVFAIL" /* ns_r_servfail */: return 2; 	// Server failure. 
    case "NXDOMAIN" /* ns_r_nxdomain */: return 3;	// Name error. 
    case "NOTIMPL" /* ns_r_notimpl */: return 4;	// Unimplemented. 
    case "REFUSED" /* ns_r_refused */: return 5;	// Operation refused. 
	/* these are for BIND_UPDATE */
    case "YXDOMAIN" /* ns_r_yxdomain */: return 6;	// Name exists 
    case "YXRRSET" /* ns_r_yxrrset */: return 7;	// RRset exists 
    case "NXRRSET" /* ns_r_nxrrset */: return 8;	// RRset does not exist 
    case "NOTAUTH" /* ns_r_notauth */: return 9;	// Not authoritative for zone 
    case "NOTZONE" /* ns_r_notzone */: return 10;	// Zone of record different from zone section 
    // ns_r_max = 11
    // The following are TSIG errors */
    case "BADVERS/SIG" /* ns_r_badvers */:	return 16;
	// The following are EDNS extended rcodes */
    // TODO: case /* ns_r_badsig */:	return "BADSIG"; // == badvers */
    case "BADKEY" /* ns_r_badkey */:	return 17;
    case "BADTIME" /* ns_r_badtime */:	return 18;

    default:
        throw new UnknownRCodeError(str, `StringToRCode: unknown rcode name "${str}"`);
    }
}

export function RRTypeToString(type: ns_type)
{
    switch (type) {
    case 0 /*ns_t_invalid*/:  return "INVALID";       // Cookie.
    case 1 /*ns_t_a*/:        return "A";             // Host address.
    case 2 /*ns_t_ns*/:       return "NS";            // Authoritative server.
//     case 3 /*ns_t_md*/:       return "MD";            // Mail destination.
//     case 4 /*ns_t_mf*/:       return "MF";            // Mail forwarder.
     case 5 /*ns_t_cname*/:    return "CNAME";         // Canonical name.
     case 6 /*ns_t_soa*/:      return "SOA";           // Start of authority zone.
//     case 7 /*ns_t_mb*/:       return "MB";            // Mailbox domain name.
//     case 8 /*ns_t_mg*/:       return "MG";            // Mail group member.
//     case 9 /*ns_t_mr*/:       return "MR";            // Mail rename name.
//     case 10 /*ns_t_null*/:     return "NULL";          // Null resource record.
//     case 11 /*ns_t_wks*/:      return "WKS";           // Well known service.
     case 12 /*ns_t_ptr*/:      return "PTR";           // Domain name pointer.
     case 13 /*ns_t_hinfo*/:    return "HINFO";         // Host information (RFC 1035 §3.3.2).
//     case 14 /*ns_t_minfo*/:    return "MINFO";         // Mailbox information.
    case 15 /*ns_t_mx*/:       return "MX";            // Mail routing information.
    case 16 /*ns_t_txt*/:      return "TXT";           // Text strings.
    case 17 /*ns_t_rp*/:       return "RP";            // Responsible person (RFC 1183 §2.2).
//     case 18 /*ns_t_afsdb*/:    return "AFSDB";         // AFS cell database.
//     case 19 /*ns_t_x25*/:      return "X25";           // X_25 calling address.
//     case 20 /*ns_t_isdn*/:     return "ISDN";          // ISDN calling address.
//     case 21 /*ns_t_rt*/:       return "RT";            // Router.
//     case 22 /*ns_t_nsap*/:     return "NSAP";          // NSAP address.
//     case 23 /*ns_t_nsap_ptr*/: return "NSAP_PTR";      // Reverse NSAP lookup (deprecated).
//     case 24 /*ns_t_sig*/:      return "SIG";           // Security signature.
//     case 25 /*ns_t_key*/:      return "KEY";           // Security key.
//     case 26 /*ns_t_px*/:       return "PX";            // X.400 mail mapping.
//     case 27 /*ns_t_gpos*/:     return "GPOS";          // Geographical position (withdrawn).
    case 28 /*ns_t_aaaa*/:     return "AAAA";          // Ip6 Address.
    case 29 /*ns_t_loc*/:      return "LOC";           // Location Information (RFC 1876).
//     case 30 /*ns_t_nxt*/:      return "NXT";           // Next domain (security).
//     case 31 /*ns_t_eid*/:      return "EID";           // Endpoint identifier.
//     case 32 /*ns_t_nimloc*/:   return "NIMLOC";        // Nimrod Locator.
    case 33 /*ns_t_srv*/:      return "SRV";           // Server Selection.
//     case 34 /*ns_t_atma*/:     return "ATMA";          // ATM Address
    case 35 /*ns_t_naptr*/:    return "NAPTR";         // Naming Authority PoinTeR
//     case 36 /*ns_t_kx*/:       return "KX";            // Key Exchange
    case 37 /*ns_t_cert*/:     return "CERT";          // Certificate record (RFC 4398)
//     case 38 /*ns_t_a6*/:       return "A6";            // IPv6 address(deprecates AAAA)
    case 39 /*ns_t_dname*/:    return "DNAME";         // Non-terminal DNAME (RFC 6672)
//     case 40 /*ns_t_sink*/:     return "SINK";          // Kitchen sink (experimentatl)
    case 41 /*ns_t_opt*/:      return "OPT";           // EDNS0 option (meta-RR, RFC 6891)
//     case 42 /*ns_t_apl*/:	return "APL";
    case 43 /*ns_t_ds*/:	return "DS";
    case 44 /*ns_t_sshfp*/:	return "SSHFP";         // SSH Fingerprint (RFC 4255)
//     case 45 /*ns_t_ipseckey*/:	return "IPSECKEY";
    case 46 /*ns_t_rrsig*/:	return "RRSIG";
    case 47 /*ns_t_nsec*/:	return "NSEC";
    case 48 /*ns_t_dnskey*/:	return "DNSKEY";

//     case 49 /*ns_t_dhcid*/:	return "DHCID";
    case 50 /*ns_t_nsec3*/:	return "NSEC3";
    case 51 /*ns_t_nsec3param*/:return "NSEC3PARAM";    // NSEC3 parameters (RFC 5155)
    case 52 /*ns_t_tlsa*/:	return "TLSA";
    case 53 /*ns_t_smimea*/:	return "SMIMEA";
//     case 55 /*ns_t_hip*/:	return "HIP";
    case 59 /*ns_t_cds*/:	return "CDS";           // Child DS (RFC 7344)
    case 60 /*ns_t_cdnskey*/:	return "CDNSKEY";       // Child DNSKEY (RFC 7344)
    case 61 /*ns_t_openpgpkey*/:return "OPENPGPKEY";   // OpenPGP public key (RFC 7929)
    case 62 /*ns_t_csync*/:	return "CSYNC";         // Child-to-Parent Sync (RFC 7477)
    case 64 /*ns_t_svcb*/:	return "SVCB";          // Service Binding (RFC 9460)
    case 65 /*ns_t_https*/:	return "HTTPS";         // HTTPS Service Binding (RFC 9460)
//     case 99 /*ns_t_spf*/:	return "SPF";
//     case 100 /*ns_t_uinfo*/:	return "UINFO";
//     case 101 /*ns_t_uid*/:	return "UID";
//     case 102 /*ns_t_gid*/:	return "GID";
//     case 103 /*ns_t_unspec*/:	return "UNSPEC";
//     case 104 /*ns_t_nid*/:	return "NID";
//     case 105 /*ns_t_l32*/:	return "L32";
//     case 106 /*ns_t_l64*/:	return "L64";
//     case 107 /*ns_t_lp*/:	return "LP";
    case 108 /*ns_t_eui48*/:	return "EUI48";         // EUI-48 address (RFC 7043)
    case 109 /*ns_t_eui64*/:	return "EUI64";         // EUI-64 address (RFC 7043)

//     case 249 /*ns_t_tkey*/:	return "TKEY";
//     case 250 /*ns_t_tsig*/:	return "TSIG";
//     case 251 /*ns_t_ixfr*/:	return "IXFR";
//     case 252 /*ns_t_axfr*/:	return "AXFR";
//     case 253 /*ns_t_mailb*/:    return "MAILB";
//     case 254 /*ns_t_maila*/:    return "MAILA";
//     case 255 /*ns_t_any*/:      return "ANY";
    case 256 /*ns_t_uri*/:      return "URI";
    case 257 /*ns_t_caa*/:      return "CAA";
//     case 258 /*ns_t_avc*/:      return "AVC";
//     case 32768 /*ns_t_ta*/:     return "TA";
//     case 32769 /*ns_t_dlv*/:    return "DLV";

    default:
        throw new UnknownRRTypeError(type, `RRTypeToString: unknown ns_type: <${type}>`);
    }
}

export function StringToRRType(str: string) : ns_type
{
    switch (str) {
    case "INVALID" /*ns_t_invalid*/:  return 0;       // Cookie.
    case "A" /*ns_t_a*/:        return 1;             // Host address.
    case "NS" /*ns_t_ns*/:       return 2;            // Authoritative server.
//     case 3 /*ns_t_md*/:       return "MD";            // Mail destination.
//     case 4 /*ns_t_mf*/:       return "MF";            // Mail forwarder.
     case "CNAME" /*ns_t_cname*/:    return 5;         // Canonical name.
     case "SOA" /*ns_t_soa*/:      return 6;           // Start of authority zone.
//     case 7 /*ns_t_mb*/:       return "MB";            // Mailbox domain name.
//     case 8 /*ns_t_mg*/:       return "MG";            // Mail group member.
//     case 9 /*ns_t_mr*/:       return "MR";            // Mail rename name.
//     case 10 /*ns_t_null*/:     return "NULL";          // Null resource record.
//     case 11 /*ns_t_wks*/:      return "WKS";           // Well known service.
     case "PTR" /*ns_t_ptr*/:      return 12;           // Domain name pointer.
     case "HINFO" /*ns_t_hinfo*/:  return 13;           // Host information (RFC 1035 §3.3.2).
//     case 14 /*ns_t_minfo*/:    return "MINFO";         // Mailbox information.
    case "MX" /*ns_t_mx*/:        return 15;           // Mail routing information.
    case "TXT" /*ns_t_txt*/:      return 16;           // Text strings.
    case "RP" /*ns_t_rp*/:        return 17;           // Responsible person (RFC 1183 §2.2).
//     case 18 /*ns_t_afsdb*/:    return "AFSDB";         // AFS cell database.
//     case 19 /*ns_t_x25*/:      return "X25";           // X_25 calling address.
//     case 20 /*ns_t_isdn*/:     return "ISDN";          // ISDN calling address.
//     case 21 /*ns_t_rt*/:       return "RT";            // Router.
//     case 22 /*ns_t_nsap*/:     return "NSAP";          // NSAP address.
//     case 23 /*ns_t_nsap_ptr*/: return "NSAP_PTR";      // Reverse NSAP lookup (deprecated).
//     case 24 /*ns_t_sig*/:      return "SIG";           // Security signature.
//     case 25 /*ns_t_key*/:      return "KEY";           // Security key.
//     case 26 /*ns_t_px*/:       return "PX";            // X.400 mail mapping.
//     case 27 /*ns_t_gpos*/:     return "GPOS";          // Geographical position (withdrawn).
    case "AAAA" /*ns_t_aaaa*/:     return 28;          // Ip6 Address.
    case "LOC" /*ns_t_loc*/:       return 29;          // Location Information (RFC 1876).
//     case 30 /*ns_t_nxt*/:      return "NXT";           // Next domain (security).
//     case 31 /*ns_t_eid*/:      return "EID";           // Endpoint identifier.
//     case 32 /*ns_t_nimloc*/:   return "NIMLOC";        // Nimrod Locator.
    case "SRV" /*ns_t_srv*/:      return 33;           // Server Selection.
//     case 34 /*ns_t_atma*/:     return "ATMA";          // ATM Address
    case "NAPTR" /*ns_t_naptr*/:    return 35;         // Naming Authority PoinTeR
//     case 36 /*ns_t_kx*/:       return "KX";            // Key Exchange
    case "CERT" /*ns_t_cert*/:     return 37;          // Certificate record (RFC 4398)
//     case 38 /*ns_t_a6*/:       return "A6";            // IPv6 address(deprecates AAAA)
    case "DNAME" /*ns_t_dname*/:    return 39;         // Non-terminal DNAME (RFC 6672)
//     case 40 /*ns_t_sink*/:     return "SINK";          // Kitchen sink (experimentatl)
    case "OPT" /*ns_t_opt*/:      return 41;           // EDNS0 option (meta-RR, RFC 6891)
//     case 42 /*ns_t_apl*/:	return "APL";
    case "DS" /*ns_t_ds*/:	return 43;
    case "SSHFP" /*ns_t_sshfp*/:	return 44;         // SSH Fingerprint (RFC 4255)
//     case 45 /*ns_t_ipseckey*/:	return "IPSECKEY";
    case "RRSIG" /*ns_t_rrsig*/:	return 46;
    case "NSEC" /*ns_t_nsec*/:	return 47;
    case "DNSKEY" /*ns_t_dnskey*/:	return 48;

//     case 49 /*ns_t_dhcid*/:	return "DHCID";
    case "NSEC3" /*ns_t_nsec3*/:	return 50;
    case "NSEC3PARAM" /*ns_t_nsec3param*/:return 51;    // NSEC3 parameters (RFC 5155)
    case "TLSA" /*ns_t_tlsa*/:	return 52;
    case "SMIMEA" /*ns_t_smimea*/:	return 53;
//     case 55 /*ns_t_hip*/:	return "HIP";
    case "CDS" /*ns_t_cds*/:	return 59;          // Child DS (RFC 7344)
    case "CDNSKEY" /*ns_t_cdnskey*/:	return 60;  // Child DNSKEY (RFC 7344)
    case "OPENPGPKEY" /*ns_t_openpgpkey*/:return 61; // OpenPGP public key (RFC 7929)
    case "CSYNC" /*ns_t_csync*/:	return 62;  // Child-to-Parent Sync (RFC 7477)
    case "SVCB" /*ns_t_svcb*/:	return 64;          // Service Binding (RFC 9460)
    case "HTTPS" /*ns_t_https*/:	return 65;      // HTTPS Service Binding (RFC 9460)
//     case 99 /*ns_t_spf*/:	return "SPF";
//     case 100 /*ns_t_uinfo*/:	return "UINFO";
//     case 101 /*ns_t_uid*/:	return "UID";
//     case 102 /*ns_t_gid*/:	return "GID";
//     case 103 /*ns_t_unspec*/:	return "UNSPEC";
//     case 104 /*ns_t_nid*/:	return "NID";
//     case 105 /*ns_t_l32*/:	return "L32";
//     case 106 /*ns_t_l64*/:	return "L64";
//     case 107 /*ns_t_lp*/:	return "LP";
    case "EUI48" /*ns_t_eui48*/:	return 108;         // EUI-48 address (RFC 7043)
    case "EUI64" /*ns_t_eui64*/:	return 109;         // EUI-64 address (RFC 7043)

//     case 249 /*ns_t_tkey*/:	return "TKEY";
//     case 250 /*ns_t_tsig*/:	return "TSIG";
//     case 251 /*ns_t_ixfr*/:	return "IXFR";
//     case 252 /*ns_t_axfr*/:	return "AXFR";
//     case 253 /*ns_t_mailb*/:    return "MAILB";
//     case 254 /*ns_t_maila*/:    return "MAILA";
//     case 255 /*ns_t_any*/:      return "ANY";
    case "URI" /*ns_t_uri*/:      return 256;
    case "CAA" /*ns_t_caa*/:      return 257;
//     case 258 /*ns_t_avc*/:      return "AVC";
//     case 32768 /*ns_t_ta*/:     return "TA";
//     case 32769 /*ns_t_dlv*/:    return "DLV";

    default:
        throw new UnknownRRTypeError(str, `StringToRRType: unknown rrtype name "${str}"`);
    }
}

export function RRClassToString(klass: ns_class)
{
    switch (klass) {
    case 0 /*ns_c_invalid*/:	return "INVALID";	// Cookie
    case 1 /*ns_c_in*/:	return "IN";		// Internet
    case 2 /*ns_c_chaos*/:	return "UNALLOC_2";		// Unallocated/unsupported
    case 3 /*ns_c_chaos*/:	return "CHAOS";		// MIT Chaos-net
    case 4 /*ns_c_hs*/:	return "HS";		// MIT Hesiod
    // Query class values which do not appear in resource records */
    case 254 /*ns_c_none*/:	return "NONE"; // for prereq. sections in update requests
    case 255 /*ns_c_any*/:	return "ANY";           // Wildcard match
    default:
        throw new UnknownRRClassError(klass, `RRClassToString: unknown ns_class: <${klass}>`);
    }
}

export function StringToRRClass(str: string) : ns_class
{
    switch (str) {
    case "INVALID" /*ns_c_invalid*/:	return 0;	// Cookie
    case "IN" /*ns_c_in*/:	            return 1;		// Internet
    case "UNALLOC_2" /*ns_c_chaos*/:	return 2;		// Unallocated/unsupported
    case "CHAOS" /*ns_c_chaos*/:	    return 3;		// MIT Chaos-net
    case "HS"/*ns_c_hs*/:	            return 4;		// MIT Hesiod
    // Query class values which do not appear in resource records */
    case "NONE" /*ns_c_none*/:	return 254; // for prereq. sections in update requests
    case "ANY" /*ns_c_any*/:	return 255;           // Wildcard match
    default:
        throw new UnknownRRClassError(str, `StringToRRClass: unknown class name "${str}"`);
    }
}
export function QTypeValidForRequest(type: ns_type): boolean {
    switch (type) {
    case 0 /*ns_t_invalid*/: return false;
    case 1 /*ns_t_a*/:
    case 2 /*ns_t_ns*/:
    case 5 /*ns_t_cname*/:
    case 6 /*ns_t_soa*/:
    case 12 /*ns_t_ptr*/:
    case 13 /*ns_t_hinfo*/:
    case 15 /*ns_t_mx*/:
    case 16 /*ns_t_txt*/:
    case 17 /*ns_t_rp*/:
    case 28 /*ns_t_aaaa*/:
    case 29 /*ns_t_loc*/:
    case 33 /*ns_t_srv*/:
    case 35 /*ns_t_naptr*/:
    case 37 /*ns_t_cert*/:
    case 39 /*ns_t_dname*/:
    case 43 /*ns_t_ds*/:
    case 44 /*ns_t_sshfp*/:
    case 46 /*ns_t_rrsig*/:
    case 47 /*ns_t_nsec*/:
    case 48 /*ns_t_dnskey*/:
    case 50 /*ns_t_nsec3*/:
    case 51 /*ns_t_nsec3param*/:
    case 52 /*ns_t_tlsa*/:
    case 53 /*ns_t_smimea*/:
    case 59 /*ns_t_cds*/:
    case 60 /*ns_t_cdnskey*/:
    case 61 /*ns_t_openpgpkey*/:
    case 62 /*ns_t_csync*/:
    case 64 /*ns_t_svcb*/:
    case 65 /*ns_t_https*/:
    case 108 /*ns_t_eui48*/:
    case 109 /*ns_t_eui64*/:
    case 256 /*ns_t_uri*/:
        return true;
    default:
        return false;
    }
}

export function QClassValidForRequest(klass: ns_class): boolean {
    switch (klass) {
    case 0 /*ns_c_invalid*/: return false;
    case 1 /*ns_c_in*/:     return true;
    case 3 /*ns_c_chaos*/:  return true;
    case 4 /*ns_c_hs*/:     return true;
    case 254 /*ns_c_none*/: return false;
    case 255 /*ns_c_any*/:  return true;
    default:
        return false;
    }
}
