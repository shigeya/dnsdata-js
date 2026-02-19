import { DNSSecZone, KeyVerifyMode } from '../lib/dnssec_zone';
import { DNSRR_DS } from '../lib/dnssec_rr';
import { RRTypeToString, StringToRRType } from '../lib/dns_type_table';
import { DNSAnswer, DNSResponse } from './resolver';
import { DoHResolver, DoHProvider } from './resolver_doh';
import { loadRootAnchors, RootAnchorDS } from '../lib/root_anchors';

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

// Decompose FQDN into delegation chain: "example.com." -> ['.', 'com.', 'example.com.']
export function decomposeFQDN(fqdn: string): string[] {
    const name = fqdn.endsWith('.') ? fqdn : fqdn + '.';
    if (name === '.') return ['.'];
    const labels = name.slice(0, -1).split('.');
    const result: string[] = ['.'];
    for (let i = labels.length - 1; i >= 0; i--) {
        result.push(labels.slice(i).join('.') + '.');
    }
    return result;
}

// Add all records from a DoH response to a DNSSecZone
function addDoHResponseToZone(zone: DNSSecZone, response: DNSResponse): number {
    let count = 0;
    const allRecords = [...response.answers, ...response.authority];
    for (const ans of allRecords) {
        try {
            const typeName = RRTypeToString(ans.type);
            const data = normalizeRecordData(typeName, ans.data);
            zone.add_rr_from_parts(ans.name, ans.TTL, 'IN', typeName, data);
            count++;
        } catch {
            // Skip records we can't parse
        }
    }
    return count;
}

// Load root trust anchors (DS records) into a zone and mark root as SEP
function loadRootAnchorsToZone(zone: DNSSecZone, details: string[]): RootAnchorDS[] {
    const { anchors, isExternal } = loadRootAnchors();
    if (isExternal) {
        details.push(`[.] Warning: Using external root anchors from ~/.dnsjs/root-anchors.json (last updated: ${anchors.lastUpdated}, source: ${anchors.source})`);
    }

    const keyTagInfo = anchors.ds.map(ds => `${ds.keyTag}/${algoName(ds.algorithm)}`).join(', ');
    details.push(`[.] Root trust anchor loaded (keytag=${keyTagInfo})`);

    // Add DS records for root KSKs to zone
    // These are stored under '.' name with the child zone being '.' itself
    for (const ds of anchors.ds) {
        const dsValue = `${ds.keyTag} ${ds.algorithm} ${ds.digestType} ${ds.digest}`;
        zone.add_rr_from_parts('.', 86400, 'IN', 'DS', dsValue);
    }

    return anchors.ds;
}

// Fetch DS for a child zone; returns description string if DS found, null if absent
async function fetchDS(
    doh: DoHResolver, zone: DNSSecZone, childZone: string, dsType: number,
): Promise<string | null> {
    const dsResp = await doh.resolve(childZone, dsType);
    const dsAnswers = dsResp.answers.filter(a => a.type === dsType);
    if (dsAnswers.length === 0) return null;
    addDoHResponseToZone(zone, dsResp);
    // DS data: "{keytag} {algorithm} {digesttype} {hexdigest}"
    return dsAnswers.map(r => {
        const parts = r.data.split(/\s+/);
        return `${parts[0]}/${algoName(parseInt(parts[1]))}`;
    }).join(', ');
}

export async function verifyDNSSECChain(
    fqdn: string,
    rrtype: number,
    primaryResponse: DNSResponse,
    dohProvider: DoHProvider = 'google',
): Promise<VerificationResult> {
    const details: string[] = [];
    const zones = new Map<string, DNSSecZone>();
    const doh = new DoHResolver(dohProvider);

    // Ensure trailing dot
    const name = fqdn.endsWith('.') ? fqdn : fqdn + '.';

    // Helper: get or create a zone for a given name
    function getZone(zoneName: string): DNSSecZone {
        let z = zones.get(zoneName);
        if (!z) {
            z = new DNSSecZone();
            zones.set(zoneName, z);
        }
        return z;
    }

    // Determine the signer zone from the primary response
    const signerDetectZone = new DNSSecZone();
    addDoHResponseToZone(signerDetectZone, primaryResponse);
    const rrsigs = signerDetectZone.find_rrsigs(name, rrtype);
    if (rrsigs.length === 0) {
        details.push('No RRSIG records found covering the queried type');
        return { verified: false, details };
    }
    const signerName = rrsigs[0].signer;

    // Full name hierarchy: e.g. ['.', 'jp.', 'ad.jp.', 'wide.ad.jp.']
    const hierarchy = decomposeFQDN(signerName);

    const dnskeyType = StringToRRType('DNSKEY');
    const dsType = StringToRRType('DS');

    // --- Step 1: Verify root DNSKEY against trust anchor ---
    const rootZone = getZone('.');

    // Load root trust anchors (DS records) into root zone
    loadRootAnchorsToZone(rootZone, details);

    try {
        const dnskeyResp = await doh.resolve('.', dnskeyType);
        const count = addDoHResponseToZone(rootZone, dnskeyResp);
        details.push(`[.] DNSKEY RRset (DoH) -> fetched ${count} records`);
    } catch (err: any) {
        details.push(`[.] DNSKEY fetch failed: ${err.message}`);
        return { verified: false, details };
    }

    // Root zone DS is in rootZone itself, so verify_delegation_signer
    // will find DS via ds_source = this (no parent needed)
    rootZone.add_sep('.');
    if (!rootZone.verify_rrset('.', dnskeyType, KeyVerifyMode.KSK)) {
        // Fallback: manual root DNSKEY verification for trust anchor bootstrap
        const dnskeyRrsigs = rootZone.find_rrsigs('.', dnskeyType);
        let rootDnskeyValid = false;
        for (const rrsig of dnskeyRrsigs) {
            const signingKey = rootZone.find_dnskey('.', rrsig.key_tag);
            if (!signingKey) continue;

            let dsMatch = false;
            const dsRRs = rootZone.find_rrset('.', dsType);
            for (const dsRR of dsRRs) {
                const handler = dsRR.get_handler();
                if (handler instanceof DNSRR_DS) {
                    const keyDigest = signingKey.get_ds_digest_data();
                    if (handler.verify_digest(keyDigest)) { dsMatch = true; break; }
                }
            }
            if (!dsMatch) continue;

            const digestTarget = rootZone.create_digest_target(rrsig, '.', dnskeyType);
            if (digestTarget && signingKey.verify(digestTarget, rrsig.signature)) {
                rootDnskeyValid = true;
                break;
            }
        }

        if (!rootDnskeyValid) {
            details.push(`[.] DNSKEY RRset RRSIG -> FAILED`);
            return { verified: false, details };
        }
    }
    details.push(`[.] DNSKEY RRset RRSIG -> VALID`);

    // --- Step 2: Walk delegation chain dynamically ---
    let parentIdx = 0; // index in hierarchy; 0 = root

    while (parentIdx < hierarchy.length - 1) {
        const parentName = hierarchy[parentIdx];
        const parentZone = getZone(parentName);
        let foundChildIdx = -1;

        for (let childIdx = parentIdx + 1; childIdx < hierarchy.length; childIdx++) {
            const childName = hierarchy[childIdx];

            // Fetch DS into parent zone
            let keyTags: string | null;
            try {
                keyTags = await fetchDS(doh, parentZone, childName, dsType);
            } catch (err: any) {
                details.push(`[${parentName} -> ${childName}] DS fetch failed: ${err.message}`);
                return { verified: false, details };
            }

            if (keyTags === null) {
                details.push(`[${parentName} -> ${childName}] DS -> not found (insecure delegation, skipping)`);
                continue;
            }

            details.push(`[${parentName} -> ${childName}] DS (DoH) -> fetched, keytag=${keyTags}`);

            // Verify DS RRSIG (signed by parent zone's keys)
            if (!parentZone.verify_rrset(childName, dsType)) {
                details.push(`[${parentName} -> ${childName}] DS RRSIG -> FAILED`);
                return { verified: false, details };
            }
            details.push(`[${parentName} -> ${childName}] DS RRSIG -> VALID`);

            // Create child zone with parent reference
            const childZone = getZone(childName);
            childZone.parent = parentZone;

            // Fetch child DNSKEY
            try {
                const dnskeyResp = await doh.resolve(childName, dnskeyType);
                const count = addDoHResponseToZone(childZone, dnskeyResp);
                details.push(`[${childName}] DNSKEY (DoH) -> fetched ${count} records`);
            } catch (err: any) {
                details.push(`[${childName}] DNSKEY fetch failed: ${err.message}`);
                return { verified: false, details };
            }

            // verify_rrset with KSK mode: verify_delegation_signer looks up DS
            // in childZone.parent (= parentZone) automatically
            if (!childZone.verify_rrset(childName, dnskeyType, KeyVerifyMode.KSK)) {
                details.push(`[${childName}] DNSKEY RRset RRSIG -> FAILED`);
                return { verified: false, details };
            }
            details.push(`[${childName}] DNSKEY RRset RRSIG -> VALID`);

            foundChildIdx = childIdx;
            break;
        }

        if (foundChildIdx === -1) {
            details.push(`No DS records found for any child zone below ${hierarchy[parentIdx]}`);
            return { verified: false, details };
        }
        parentIdx = foundChildIdx;
    }

    // --- Step 3: Verify the target RRset RRSIG ---
    const targetName = hierarchy[parentIdx];
    const targetZone = getZone(targetName);
    // Add primary response records to the target zone
    addDoHResponseToZone(targetZone, primaryResponse);
    const rrsetValid = targetZone.verify_rrset(name, rrtype);
    const typeStr = RRTypeToString(rrtype);
    const targetRrsigs = targetZone.find_rrsigs(name, rrtype);
    const rrsigAlgo = targetRrsigs.length > 0 ? ` (${algoName(targetRrsigs[0].algorithm)})` : '';
    if (rrsetValid) {
        details.push(`[${targetName}] ${typeStr} RRSIG -> VALID${rrsigAlgo}`);
        details.push(`Result: SECURE (full chain verified to root)`);
        return { verified: true, details };
    } else {
        details.push(`[${targetName}] ${typeStr} RRSIG -> FAILED${rrsigAlgo}`);
        return { verified: false, details };
    }
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
