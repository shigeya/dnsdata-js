// parseRootAnchors: the shared ~/.dnsdata/root-anchors.json format.
// dnsdata-go writes an empty list as null (a nil slice), so a file it
// produced must read as an empty array here.

import * as fs from 'fs';
import * as path from 'path';
import { parseRootAnchors, RootAnchorsFormatError } from '../../src/dnssec/root_anchors';

describe('parseRootAnchors', () => {
    it('reads null lists as empty arrays', () => {
        const a = parseRootAnchors('{"lastUpdated":"","source":"x","ds":null,"dnskeys":null}');
        expect(a.ds).toEqual([]);
        expect(a.dnskeys).toEqual([]);
    });

    it('reads the shared vector written by dnsdata-go', () => {
        const file = path.join(__dirname, '..', 'testdata', 'signed', 'root-anchors.json');
        const a = parseRootAnchors(fs.readFileSync(file, 'utf8'));
        expect(a.ds).toHaveLength(1);
        expect(a.ds[0].keyTag).toBe(37756);
        expect(a.dnskeys).toEqual([]);
    });

    it('keeps present lists', () => {
        const text = JSON.stringify({
            lastUpdated: '2024-11-05', source: 'iana',
            ds: [{ keyTag: 1, algorithm: 8, digestType: 2, digest: 'AB' }],
            dnskeys: [{ flags: 257, protocol: 3, algorithm: 8, publicKey: 'AQAB' }],
        });
        const a = parseRootAnchors(text);
        expect(a.ds[0].keyTag).toBe(1);
        expect(a.dnskeys[0].flags).toBe(257);
    });

    it.each([
        ['not JSON', '{'],
        ['not an object', '[]'],
        ['ds not a list', '{"lastUpdated":"","source":"x","ds":{},"dnskeys":[]}'],
        ['dnskeys not a list', '{"lastUpdated":"","source":"x","ds":[],"dnskeys":"x"}'],
    ])('rejects %s', (_name, text) => {
        expect(() => parseRootAnchors(text)).toThrow(RootAnchorsFormatError);
    });
});
