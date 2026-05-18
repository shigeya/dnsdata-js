// Fetch and update IANA root trust anchors.
//
// Downloads root-anchors.xml from IANA, parses DS records, fetches
// the root DNSKEY rrset via DoH (using the new lib/resolver/doh
// client), and writes ~/.dnsdata/root-anchors.json. Stays in cli/
// because it owns user-facing filesystem and stderr output.

import * as https from 'https';
import { DoHClient } from '../resolver/doh';
import { StringToRRType } from '../types/dns_type_table';
import {
    RootAnchors,
    RootAnchorDS,
    RootAnchorDNSKEY,
    loadRootAnchors,
    saveRootAnchors,
    getRootAnchorsPath,
} from '../dnssec/root_anchors';

function https_get(url: string): Promise<string> {
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

function parse_root_anchors_xml(xml: string): RootAnchorDS[] {
    const results: RootAnchorDS[] = [];
    const key_digest_re = /<KeyDigest[^>]*>([\s\S]*?)<\/KeyDigest>/g;
    let match;
    while ((match = key_digest_re.exec(xml)) !== null) {
        const block = match[1];
        const key_tag = extract_xml_field(block, 'KeyTag');
        const algorithm = extract_xml_field(block, 'Algorithm');
        const digest_type = extract_xml_field(block, 'DigestType');
        const digest = extract_xml_field(block, 'Digest');

        if (key_tag && algorithm && digest_type && digest) {
            results.push({
                keyTag: parseInt(key_tag),
                algorithm: parseInt(algorithm),
                digestType: parseInt(digest_type),
                digest: digest.replace(/\s+/g, '').toUpperCase(),
            });
        }
    }
    return results;
}

function extract_xml_field(block: string, tag: string): string | null {
    const re = new RegExp(`<${tag}>\\s*([^<]+?)\\s*</${tag}>`);
    const m = block.match(re);
    return m ? m[1].trim() : null;
}

// fetch_and_update_root_anchors fetches IANA's root-anchors.xml, runs
// a DoH DNSKEY lookup against the root, and rewrites the on-disk
// anchor file. Providers default to DoHClient's built-in list
// (Google → Cloudflare → Quad9).
export async function fetch_and_update_root_anchors(providers?: readonly string[]): Promise<void> {
    console.error('Fetching root-anchors.xml from IANA...');
    const xml = await https_get('https://data.iana.org/root-anchors/root-anchors.xml');
    const ds_records = parse_root_anchors_xml(xml);
    if (ds_records.length === 0) {
        throw new Error('No DS records found in root-anchors.xml');
    }
    console.error(`Found ${ds_records.length} DS record(s): keytags=${ds_records.map(d => d.keyTag).join(', ')}`);

    console.error('Fetching root DNSKEY via DoH...');
    const doh = providers && providers.length > 0
        ? new DoHClient({ providers })
        : new DoHClient();
    const dnskey_type = StringToRRType('DNSKEY');
    const records = await doh.resolve('.', dnskey_type);

    const dnskeys: RootAnchorDNSKEY[] = [];
    for (const rr of records) {
        if (rr.type !== dnskey_type) continue;
        // ResourceRecord.value is the rdata presentation form
        // "{flags} {protocol} {algorithm} {base64key}" — the wire
        // decoder always emits numeric algorithm, so no mnemonic
        // normalisation is needed.
        const parts = rr.value.split(/\s+/);
        if (parts.length < 4) continue;
        dnskeys.push({
            flags: parseInt(parts[0]),
            protocol: parseInt(parts[1]),
            algorithm: parseInt(parts[2]),
            publicKey: parts.slice(3).join(''),
        });
    }
    console.error(`Found ${dnskeys.length} DNSKEY record(s)`);

    const { anchors: current_anchors } = loadRootAnchors();

    const new_anchors: RootAnchors = {
        lastUpdated: new Date().toISOString().slice(0, 10),
        source: 'iana',
        ds: ds_records,
        dnskeys,
    };

    const current_keytags = current_anchors.ds.map(d => d.keyTag).sort();
    const new_keytags = new_anchors.ds.map(d => d.keyTag).sort();
    if (JSON.stringify(current_keytags) !== JSON.stringify(new_keytags)) {
        console.error(`DS key tags changed: ${current_keytags.join(', ')} -> ${new_keytags.join(', ')}`);
    } else {
        console.error(`DS key tags unchanged: ${new_keytags.join(', ')}`);
    }

    saveRootAnchors(new_anchors);
    console.error(`Root anchors saved to ${getRootAnchorsPath()}`);
}
