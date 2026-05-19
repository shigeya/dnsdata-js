// Verifier cache (UP-008) — ports dnsdata-go verifier/cache_test.go.
//
// The fixtures here are deliberately tiny: real chain-walking is
// already exercised in verifier.spec.ts, so this file focuses on the
// cache surface (MemoryCache hit / miss / NODATA / keying) and the
// integration contract (a second validate() against the same name
// makes zero resolver calls when a cache is attached).

import * as crypto from 'crypto';

import { DNSSecZone } from '../../src/dnssec/dnssec_zone';
import { DNSKey, RRSig } from '../../src/dnssec/dnssec_rr';
import { ResourceRecord } from '../../src/zone/dns_zone';
import { StringToRRType } from '../../src/types/dns_type_table';
import { RootAnchors } from '../../src/dnssec/root_anchors';
import {
    Verifier,
    Verdict,
    Resolver,
    MemoryCache,
    Cache,
} from '../../src/verifier';

const TYPE_DNSKEY = StringToRRType('DNSKEY');
const TYPE_RRSIG = StringToRRType('RRSIG');
const TYPE_DS = StringToRRType('DS');
const TYPE_A = StringToRRType('A');
const TYPE_AAAA = StringToRRType('AAAA');

const INCEPTION = 1000000000;
const EXPIRE    = 2000000000;

//////////////////////////////////////////////////////////// fixtures

interface ZoneSetup {
    apex: string;
    zone: DNSSecZone;
    ksk: DNSKey;
}

function rsa_key_b64(privateKey: crypto.KeyObject, publicKey: crypto.KeyObject): string {
    const jwk = publicKey.export({ format: 'jwk' } as { format: 'jwk' }) as { n: string; e: string };
    const n = Buffer.from(jwk.n, 'base64url');
    const e = Buffer.from(jwk.e, 'base64url');
    void privateKey;
    return Buffer.concat([Buffer.from([e.length]), e, n]).toString('base64');
}

function make_zone(apex: string): ZoneSetup {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const keyB64 = rsa_key_b64(privateKey, publicKey);
    const zone = new DNSSecZone();
    const apexLabel = apex;
    zone.add_rr_from_parts(apexLabel, 3600, 'IN', 'SOA',
        `ns1${apex === '.' ? '.' : '.' + apex} admin${apex === '.' ? '.' : '.' + apex} 2021010101 3600 900 604800 86400`);
    zone.add_rr_from_parts(apexLabel, 3600, 'IN', 'DNSKEY', `257 3 8 ${keyB64}`);
    const dnskeyRR = zone.find_rr(apexLabel, TYPE_DNSKEY)!;
    const ksk = dnskeyRR.get_handler() as DNSKey;
    ksk.set_private_key(privateKey);
    const rrsig = zone.sign_rr(apexLabel, 3600, TYPE_DNSKEY, ksk, INCEPTION, EXPIRE);
    if (rrsig) zone.add_rr(rrsig);
    return { apex: apexLabel, zone, ksk };
}

function delegate(parent: ZoneSetup, child: ZoneSetup): void {
    const dsInput = child.ksk.get_ds_digest_data();
    const dsHash = crypto.createHash('sha256').update(Buffer.from(dsInput)).digest();
    parent.zone.add_rr_from_parts(child.apex, 3600, 'IN', 'DS',
        `${child.ksk.key_tag} ${child.ksk.algorithm} 2 ${dsHash.toString('hex')}`);
    const rrsig = parent.zone.sign_rr(child.apex, 3600, TYPE_DS, parent.ksk, INCEPTION, EXPIRE);
    if (rrsig) parent.zone.add_rr(rrsig);
}

function add_signed(setup: ZoneSetup, label: string, type: string, value: string): void {
    setup.zone.add_rr_from_parts(label, 3600, 'IN', type, value);
    const typeNum = StringToRRType(type);
    const rrsig = setup.zone.sign_rr(label, 3600, typeNum, setup.ksk, INCEPTION, EXPIRE);
    if (rrsig) setup.zone.add_rr(rrsig);
}

function trust_anchor_for(setup: ZoneSetup): RootAnchors {
    const dsInput = setup.ksk.get_ds_digest_data();
    const dsHash = crypto.createHash('sha256').update(Buffer.from(dsInput)).digest();
    return {
        lastUpdated: '2026-01-01',
        source: 'test',
        ds: [{
            keyTag: setup.ksk.key_tag,
            algorithm: setup.ksk.algorithm,
            digestType: 2,
            digest: dsHash.toString('hex'),
        }],
        dnskeys: [],
    };
}

// Resolver that scans signed in-memory zones and records every
// query, so tests can assert how many times the underlying transport
// was consulted.
class CountingResolver implements Resolver {
    public queries: { name: string; qtype: number }[] = [];

    constructor(private readonly zones: DNSSecZone[]) {}

    async query(name: string, qtype: number): Promise<ResourceRecord[]> {
        this.queries.push({ name, qtype });
        const out: ResourceRecord[] = [];
        for (const z of this.zones) {
            out.push(...z.find_rrset(name, qtype));
            for (const rr of z.find_rrset(name, TYPE_RRSIG)) {
                const handler = rr.get_handler();
                if (handler instanceof RRSig && handler.type_covered === qtype) {
                    out.push(rr);
                }
            }
        }
        return out;
    }
}

function build_chain(): { resolver: CountingResolver; anchors: RootAnchors } {
    const root = make_zone('.');
    const com = make_zone('com.');
    const leaf = make_zone('example.com.');

    delegate(root, com);
    delegate(com, leaf);

    add_signed(leaf, 'www.example.com.', 'A', '192.0.2.10');
    add_signed(leaf, 'example.com.', 'A', '192.0.2.1');

    return {
        resolver: new CountingResolver([root.zone, com.zone, leaf.zone]),
        anchors: trust_anchor_for(root),
    };
}

function fake_rr(): ResourceRecord {
    // Use the existing ResourceRecord constructor via DNSSecZone — it
    // is the cheapest way to mint a valid RR for cache unit tests.
    const z = new DNSSecZone();
    z.add_rr_from_parts('example.com.', 300, 'IN', 'A', '192.0.2.1');
    return z.find_rr('example.com.', TYPE_A)!;
}

//////////////////////////////////////////////////////////// MemoryCache unit tests

describe('MemoryCache', () => {
    it('returns undefined for a miss', () => {
        const c = new MemoryCache();
        expect(c.get('example.com.', TYPE_A)).toBeUndefined();
        expect(c.size).toBe(0);
    });

    it('round-trips a put / get', () => {
        const c = new MemoryCache();
        const rr = fake_rr();
        c.put('example.com.', TYPE_A, [rr]);
        const got = c.get('example.com.', TYPE_A);
        expect(got).toBeDefined();
        expect(got).toHaveLength(1);
        expect(got![0]).toBe(rr);
        expect(c.size).toBe(1);
    });

    // NODATA (empty array) MUST round-trip as a hit so callers can
    // distinguish "we asked and got nothing" from "we never asked".
    it('treats an empty array as a NODATA hit', () => {
        const c = new MemoryCache();
        c.put('nodata.example.com.', TYPE_A, []);
        const got = c.get('nodata.example.com.', TYPE_A);
        expect(got).toBeDefined();
        expect(got).toHaveLength(0);
    });

    // Different qtypes at the same name are separate entries.
    it('keys by both name and qtype', () => {
        const c = new MemoryCache();
        const aRR = fake_rr();
        c.put('example.com.', TYPE_A, [aRR]);
        c.put('example.com.', TYPE_AAAA, []);
        expect(c.get('example.com.', TYPE_A)).toHaveLength(1);
        expect(c.get('example.com.', TYPE_AAAA)).toHaveLength(0);
        expect(c.get('example.com.', TYPE_DS)).toBeUndefined();
    });
});

//////////////////////////////////////////////////////////// Integration with Verifier

describe('Verifier with cache', () => {
    it('avoids resolver calls when the same name is validated twice', async () => {
        const { resolver, anchors } = build_chain();
        const cache = new MemoryCache();
        const v = new Verifier({ resolver, trustAnchors: anchors, cache });

        const first = await v.validate('www.example.com.', TYPE_A);
        expect(first.verdict).toBe(Verdict.Secure);
        const firstCalls = resolver.queries.length;
        expect(firstCalls).toBeGreaterThan(0);

        const second = await v.validate('www.example.com.', TYPE_A);
        expect(second.verdict).toBe(Verdict.Secure);
        expect(resolver.queries.length).toBe(firstCalls);
        expect(cache.size).toBeGreaterThan(0);
    });

    // A different leaf in the same chain shares the root + TLD
    // lookups via the cache. The new leaf still needs to be fetched,
    // so we expect a smaller (but non-zero) delta on the second call.
    it('shares ancestor lookups across different leaves', async () => {
        const { resolver, anchors } = build_chain();
        const cache = new MemoryCache();
        const v = new Verifier({ resolver, trustAnchors: anchors, cache });

        await v.validate('www.example.com.', TYPE_A);
        const firstCalls = resolver.queries.length;

        await v.validate('example.com.', TYPE_A);
        const delta = resolver.queries.length - firstCalls;
        expect(delta).toBeGreaterThan(0);
        expect(delta).toBeLessThan(firstCalls);
    });

    // No `cache` option at all (and explicit `cache: undefined`)
    // MUST behave exactly like the cache-less code path.
    it('ignores a nullish cache option', async () => {
        const { resolver, anchors } = build_chain();
        const v = new Verifier({ resolver, trustAnchors: anchors, cache: undefined });

        const result = await v.validate('www.example.com.', TYPE_A);
        expect(result.verdict).toBe(Verdict.Secure);
        expect(resolver.queries.length).toBeGreaterThan(0);
    });

    // A pathological Cache that always returns undefined falls
    // straight through to the resolver and behaves identically.
    it('passes through when Cache.get always misses', async () => {
        const { resolver, anchors } = build_chain();
        const alwaysMiss: Cache = {
            get: () => undefined,
            put: () => { /* noop */ },
        };
        const v = new Verifier({ resolver, trustAnchors: anchors, cache: alwaysMiss });

        const first = await v.validate('www.example.com.', TYPE_A);
        const firstCalls = resolver.queries.length;
        const second = await v.validate('www.example.com.', TYPE_A);

        expect(first.verdict).toBe(Verdict.Secure);
        expect(second.verdict).toBe(Verdict.Secure);
        expect(resolver.queries.length).toBe(firstCalls * 2);
    });
});
