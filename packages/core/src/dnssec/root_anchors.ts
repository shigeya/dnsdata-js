// Root Trust Anchors for DNSSEC chain validation
//
// Contains built-in IANA root trust anchor data (DS records).
// External overrides can be stored in ~/.dnsdata/root-anchors.json.
// This location is shared with sibling implementations (e.g. dnsdata-go).

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { CustomError } from 'ts-custom-error';

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

// A root-anchors document that is not JSON or not of the RootAnchors
// shape. Mirrors dnsdata-go `dnssec.ErrAnchors`.
export class RootAnchorsFormatError extends CustomError {
    public constructor(message?: string) {
        super(message);
    }
}

// Returns field as an array; null (how dnsdata-go writes an empty
// list) and a missing field read as empty.
function list_field<T>(doc: Record<string, unknown>, field: string): T[] {
    const v = doc[field];
    if (v === null || v === undefined) return [];
    if (!Array.isArray(v)) throw new RootAnchorsFormatError(`root anchors: ${field} is not a list`);
    return v as T[];
}

// Parses a root-anchors JSON document, the format shared with
// dnsdata-go. Throws RootAnchorsFormatError for anything else.
export function parseRootAnchors(text: string): RootAnchors {
    let doc: unknown;
    try {
        doc = JSON.parse(text);
    } catch (e) {
        throw new RootAnchorsFormatError(`root anchors: ${(e as Error).message}`);
    }
    if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) {
        throw new RootAnchorsFormatError('root anchors: not a JSON object');
    }
    const obj = doc as Record<string, unknown>;
    return {
        lastUpdated: typeof obj.lastUpdated === 'string' ? obj.lastUpdated : '',
        source: typeof obj.source === 'string' ? obj.source : '',
        ds: list_field<RootAnchorDS>(obj, 'ds'),
        dnskeys: list_field<RootAnchorDNSKEY>(obj, 'dnskeys'),
    };
}

export function getRootAnchorsPath(): string {
    return path.join(os.homedir(), '.dnsdata', 'root-anchors.json');
}

export function loadRootAnchors(): LoadedRootAnchors {
    const extPath = getRootAnchorsPath();
    try {
        if (fs.existsSync(extPath)) {
            const anchors = parseRootAnchors(fs.readFileSync(extPath, 'utf-8'));
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
