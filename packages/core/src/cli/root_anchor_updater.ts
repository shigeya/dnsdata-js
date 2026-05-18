// Fetch and update IANA root trust anchors
//
// Downloads root-anchors.xml from IANA, parses DS records,
// fetches root DNSKEY via DoH, and saves to ~/.dnsdata/root-anchors.json.

import * as https from 'https';
import { DoHResolver, DoHProvider } from './resolver_doh';
import { StringToRRType } from '../lib/dns_type_table';
import {
    RootAnchors,
    RootAnchorDS,
    RootAnchorDNSKEY,
    loadRootAnchors,
    saveRootAnchors,
    getRootAnchorsPath,
} from '../lib/root_anchors';

function httpsGet(url: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const req = https.get(url, (res) => {
            if (res.statusCode !== 200) {
                reject(new Error(`HTTP ${res.statusCode} from ${url}`));
                res.resume();
                return;
            }
            const chunks: Buffer[] = [];
            res.on('data', (chunk: Buffer) => chunks.push(chunk));
            res.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
        });
        req.on('error', reject);
        req.setTimeout(15000, () => {
            req.destroy(new Error('Request timeout'));
        });
    });
}

// Simple XML parser for root-anchors.xml — extract KeyDigest entries
function parseRootAnchorsXML(xml: string): RootAnchorDS[] {
    const results: RootAnchorDS[] = [];
    // Match each <KeyDigest ...>...</KeyDigest> block
    const keyDigestRe = /<KeyDigest[^>]*>([\s\S]*?)<\/KeyDigest>/g;
    let match;
    while ((match = keyDigestRe.exec(xml)) !== null) {
        const block = match[1];
        const keyTag = extractXMLField(block, 'KeyTag');
        const algorithm = extractXMLField(block, 'Algorithm');
        const digestType = extractXMLField(block, 'DigestType');
        const digest = extractXMLField(block, 'Digest');

        if (keyTag && algorithm && digestType && digest) {
            results.push({
                keyTag: parseInt(keyTag),
                algorithm: parseInt(algorithm),
                digestType: parseInt(digestType),
                digest: digest.replace(/\s+/g, '').toUpperCase(),
            });
        }
    }
    return results;
}

function extractXMLField(block: string, tag: string): string | null {
    const re = new RegExp(`<${tag}>\\s*([^<]+?)\\s*</${tag}>`);
    const m = block.match(re);
    return m ? m[1].trim() : null;
}

// Algorithm mnemonic to number mapping (for normalizing DNSKEY data from DoH)
const ALGO_NAME_TO_NUM: Record<string, string> = {
    'RSAMD5': '1', 'DH': '2', 'DSA': '3', 'RSASHA1': '5',
    'DSA-NSEC3-SHA1': '6', 'RSASHA1-NSEC3-SHA1': '7', 'RSASHA256': '8',
    'RSASHA512': '10', 'ECC-GOST': '12', 'ECDSAP256SHA256': '13',
    'ECDSAP384SHA384': '14', 'ED25519': '15', 'ED448': '16',
};

export async function fetchAndUpdateRootAnchors(dohProvider: DoHProvider): Promise<void> {
    console.error('Fetching root-anchors.xml from IANA...');

    // Fetch IANA root-anchors.xml
    const xml = await httpsGet('https://data.iana.org/root-anchors/root-anchors.xml');
    const dsRecords = parseRootAnchorsXML(xml);

    if (dsRecords.length === 0) {
        throw new Error('No DS records found in root-anchors.xml');
    }

    console.error(`Found ${dsRecords.length} DS record(s): keytags=${dsRecords.map(d => d.keyTag).join(', ')}`);

    // Fetch root DNSKEY via DoH
    console.error('Fetching root DNSKEY via DoH...');
    const doh = new DoHResolver(dohProvider);
    const dnskeyType = StringToRRType('DNSKEY');
    const dnskeyResp = await doh.resolve('.', dnskeyType);

    const dnskeys: RootAnchorDNSKEY[] = [];
    for (const ans of dnskeyResp.answers) {
        if (ans.type === dnskeyType) {
            // Parse: "{flags} {protocol} {algorithm} {base64key}"
            const parts = ans.data.split(/\s+/);
            if (parts.length >= 4) {
                let algo = parts[2];
                const algoNum = ALGO_NAME_TO_NUM[algo.toUpperCase()];
                if (algoNum) algo = algoNum;
                dnskeys.push({
                    flags: parseInt(parts[0]),
                    protocol: parseInt(parts[1]),
                    algorithm: parseInt(algo),
                    publicKey: parts.slice(3).join(''),
                });
            }
        }
    }

    console.error(`Found ${dnskeys.length} DNSKEY record(s)`);

    // Load current anchors for comparison
    const { anchors: currentAnchors } = loadRootAnchors();

    const newAnchors: RootAnchors = {
        lastUpdated: new Date().toISOString().slice(0, 10),
        source: 'iana',
        ds: dsRecords,
        dnskeys: dnskeys,
    };

    // Show diff
    const currentKeyTags = currentAnchors.ds.map(d => d.keyTag).sort();
    const newKeyTags = newAnchors.ds.map(d => d.keyTag).sort();
    if (JSON.stringify(currentKeyTags) !== JSON.stringify(newKeyTags)) {
        console.error(`DS key tags changed: ${currentKeyTags.join(', ')} -> ${newKeyTags.join(', ')}`);
    } else {
        console.error(`DS key tags unchanged: ${newKeyTags.join(', ')}`);
    }

    // Save
    saveRootAnchors(newAnchors);
    console.error(`Root anchors saved to ${getRootAnchorsPath()}`);
}
