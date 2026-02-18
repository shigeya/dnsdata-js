import { DNSSecZone } from '../lib/dnssec_zone';
import { DNSKey, RRSig } from '../lib/dnssec_rr';
import { RRTypeToString, StringToRRType } from '../lib/dns_type_table';
import { DNSAnswer, DNSResponse } from './resolver';
import { DoHResolver, DoHProvider } from './resolver_doh';

export interface VerificationResult {
    verified: boolean;
    details: string[];
}

const ALGO_NAMES: Record<number, string> = {
    5: 'RSASHA1',
    7: 'RSASHA1-NSEC3-SHA1',
    8: 'RSASHA256',
    10: 'RSASHA512',
    13: 'ECDSAP256SHA256',
    14: 'ECDSAP384SHA384',
    15: 'ED25519',
    16: 'ED448',
};

function algoName(algo: number): string {
    return ALGO_NAMES[algo] || `ALG${algo}`;
}

const ALGO_NAME_TO_NUM: Record<string, string> = {
    'RSAMD5': '1',
    'DH': '2',
    'DSA': '3',
    'RSASHA1': '5',
    'DSA-NSEC3-SHA1': '6',
    'RSASHA1-NSEC3-SHA1': '7',
    'RSASHA256': '8',
    'RSASHA512': '10',
    'ECC-GOST': '12',
    'ECDSAP256SHA256': '13',
    'ECDSAP384SHA384': '14',
    'ED25519': '15',
    'ED448': '16',
};

function normalizeRecordData(typeName: string, data: string): string {
    if (typeName === 'RRSIG') {
        // Split into fields: TypeCovered Algorithm Labels OriginalTTL ...
        const parts = data.split(/\s+/);
        if (parts.length < 2) return data;
        // Normalize covered type name to uppercase (Google returns lowercase)
        parts[0] = parts[0].toUpperCase();
        // Normalize algorithm mnemonic to numeric (Cloudflare returns mnemonics)
        const algoNum = ALGO_NAME_TO_NUM[parts[1].toUpperCase()];
        if (algoNum) {
            parts[1] = algoNum;
        }
        return parts.join(' ');
    }
    if (typeName === 'DNSKEY') {
        // DNSKEY: "{flags} {protocol} {algorithm} {base64key}"
        // Algorithm field (3rd) might be mnemonic
        const parts = data.split(/\s+/);
        if (parts.length >= 3) {
            const algoNum = ALGO_NAME_TO_NUM[parts[2].toUpperCase()];
            if (algoNum) {
                parts[2] = algoNum;
            }
        }
        return parts.join(' ');
    }
    if (typeName === 'DS') {
        // DS: "{keytag} {algorithm} {digesttype} {hexdigest}"
        // Algorithm field (2nd) might be mnemonic
        const parts = data.split(/\s+/);
        if (parts.length >= 2) {
            const algoNum = ALGO_NAME_TO_NUM[parts[1].toUpperCase()];
            if (algoNum) {
                parts[1] = algoNum;
            }
        }
        return parts.join(' ');
    }
    return data;
}

function extractZoneName(fqdn: string): string {
    // For a FQDN like "www.example.com.", the zone is typically "example.com."
    // But for simplicity, we try the FQDN itself first (works when querying zone apex).
    // The RRSIG signer field tells us the actual zone.
    return fqdn;
}

export async function verifyDNSSEC(
    fqdn: string,
    rrtype: number,
    primaryResponse: DNSResponse,
    dohProvider: DoHProvider = 'google',
): Promise<VerificationResult> {
    const details: string[] = [];
    const zone = new DNSSecZone();

    // Ensure trailing dot
    const name = fqdn.endsWith('.') ? fqdn : fqdn + '.';

    // Add all answers and authority records to the zone
    const allRecords = [...primaryResponse.answers, ...primaryResponse.authority];
    for (const ans of allRecords) {
        try {
            const typeName = RRTypeToString(ans.type);
            // Normalize RRSIG data: DoH providers may return lowercase type names
            // (e.g., "a 13 2 300 ..." instead of "A 13 2 300 ...")
            const data = normalizeRecordData(typeName, ans.data);
            zone.add_rr_from_parts(ans.name, ans.TTL, 'IN', typeName, data);
        } catch {
            // Skip records we can't parse
        }
    }

    // Find RRSIGs covering our target type
    const rrsigs = zone.find_rrsigs(name, rrtype);
    if (rrsigs.length === 0) {
        details.push('No RRSIG records found covering the queried type');
        return { verified: false, details };
    }

    // Determine signer (zone name) from the RRSIG
    const signerName = rrsigs[0].signer;
    details.push(`RRSIG: keytag=${rrsigs[0].key_tag}, algo=${rrsigs[0].algorithm} (${algoName(rrsigs[0].algorithm)}), signer=${signerName}`);

    // Fetch DNSKEY records for the signer zone via DoH
    const doh = new DoHResolver(dohProvider);
    const dnskeyType = StringToRRType('DNSKEY');
    try {
        const dnskeyResponse = await doh.resolve(signerName, dnskeyType);
        for (const ans of [...dnskeyResponse.answers, ...dnskeyResponse.authority]) {
            try {
                const typeName = RRTypeToString(ans.type);
                const data = normalizeRecordData(typeName, ans.data);
                zone.add_rr_from_parts(ans.name, ans.TTL, 'IN', typeName, data);
            } catch {
                // Skip unparseable records
            }
        }
    } catch (err: any) {
        details.push(`Failed to fetch DNSKEY for ${signerName}: ${err.message}`);
        return { verified: false, details };
    }

    // Find the DNSKEY matching the RRSIG key tag
    const dnskey = zone.find_dnskey(signerName, rrsigs[0].key_tag);
    if (dnskey) {
        const flagDesc = dnskey.is_secure_entry_point() ? 'KSK/CSK' : 'ZSK';
        details.push(`DNSKEY: keytag=${dnskey.key_tag}, flags=${dnskey.flags} (${flagDesc}) -> FOUND`);
    } else {
        details.push(`DNSKEY: keytag=${rrsigs[0].key_tag} -> NOT FOUND`);
        return { verified: false, details };
    }

    // Mark signer as trust anchor (SEP) for verification
    zone.add_sep(signerName);

    // Verify the RRset
    try {
        const result = zone.verify_rrset(name, rrtype);
        if (result) {
            details.push('RRSIG verification -> VALID');
        } else {
            details.push('RRSIG verification -> FAILED');
        }
        return { verified: result, details };
    } catch (err: any) {
        details.push(`Verification error: ${err.message}`);
        return { verified: false, details };
    }
}
