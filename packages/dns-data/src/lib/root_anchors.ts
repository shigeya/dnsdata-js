// Root Trust Anchors for DNSSEC chain validation
//
// Contains built-in IANA root trust anchor data (DS records).
// External overrides can be stored in ~/.dnsjs/root-anchors.json.

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

export interface RootAnchorDS {
    keyTag: number;
    algorithm: number;
    digestType: number;
    digest: string;
}

export interface RootAnchorDNSKEY {
    flags: number;
    protocol: number;
    algorithm: number;
    publicKey: string;  // base64
}

export interface RootAnchors {
    lastUpdated: string;        // ISO date
    source: string;             // "builtin" | "iana"
    ds: RootAnchorDS[];
    dnskeys: RootAnchorDNSKEY[];
}

export interface LoadedRootAnchors {
    anchors: RootAnchors;
    isExternal: boolean;
}

// Built-in default from IANA root-anchors.xml
// Key Tag 20326: Root KSK-2017 (active since 2017-02-02)
// Key Tag 38696: Root KSK-2024 (active since 2024-07-18)
export const BUILTIN_ROOT_ANCHORS: RootAnchors = {
    lastUpdated: '2024-11-05',
    source: 'builtin',
    ds: [
        {
            keyTag: 20326,
            algorithm: 8,
            digestType: 2,
            digest: 'E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D',
        },
        {
            keyTag: 38696,
            algorithm: 8,
            digestType: 2,
            digest: '683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16',
        },
    ],
    dnskeys: [],  // DNSKEY records are fetched via DoH during chain verification
};

export function getRootAnchorsPath(): string {
    return path.join(os.homedir(), '.dnsjs', 'root-anchors.json');
}

export function loadRootAnchors(): LoadedRootAnchors {
    const extPath = getRootAnchorsPath();
    try {
        if (fs.existsSync(extPath)) {
            const data = fs.readFileSync(extPath, 'utf-8');
            const anchors: RootAnchors = JSON.parse(data);
            return { anchors, isExternal: true };
        }
    } catch {
        // Fall through to built-in
    }
    return { anchors: BUILTIN_ROOT_ANCHORS, isExternal: false };
}

export function saveRootAnchors(anchors: RootAnchors): void {
    const extPath = getRootAnchorsPath();
    const dir = path.dirname(extPath);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(extPath, JSON.stringify(anchors, null, 2), 'utf-8');
}
