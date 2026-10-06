// KSK authentication tests for the chain walker.
//
// A zone's DNSKEY rrset counts as authenticated only when an RRSIG over
// it verifies with a DNSKEY that is itself authenticated: its DS digest
// matches the validated parent DS rrset, or (at the root) it matches a
// configured trust anchor. These tests inject keys into the DNSKEY
// rrset, tamper with the KSK signature, drop the SEP flag from a real
// KSK, and collide key tags, at both a child zone and the root.

import * as crypto from 'crypto';

import { DNSSecZone } from '../../src/dnssec/dnssec_zone';
import { DNSKey, RRSig } from '../../src/dnssec/dnssec_rr';
import { ResourceRecord } from '../../src/zone/dns_zone';
import { StringToRRType } from '../../src/types/dns_type_table';
import { RootAnchors } from '../../src/dnssec/root_anchors';
import { Verifier, Verdict, Resolver, Result } from '../../src/verifier';

const TYPE_DNSKEY = StringToRRType('DNSKEY');
const TYPE_DS = StringToRRType('DS');
const TYPE_RRSIG = StringToRRType('RRSIG');
const TYPE_A = StringToRRType('A');

const INCEPTION = 1000000000;
const EXPIRE    = 2000000000;
const NOW       = new Date(1500000000 * 1000);
const TTL       = 3600;

const FLAGS_KSK = 257;
const FLAGS_ZSK = 256;
const ALGO_RSASHA256 = 8;
const ALGO_ED25519 = 15;
const DNSKEY_PROTOCOL = 3;
const MAX_COLLISION_TRIES = 20000;

const CHILD = 'example.';
const CHILD_ADDR = '192.0.2.1';
const ATTACKER_ADDR = '198.51.100.66';

//////////////////////////////////////////////////////////// fixtures

interface ZoneSetup {
    apex: string;
    zone: DNSSecZone;
    ksk: DNSKey;
}

interface ZoneOptions {
    kskFlags?: number;
    tamperDnskeySig?: boolean;
}

function rsa_key_b64(publicKey: crypto.KeyObject): string {
    const jwk = publicKey.export({ format: 'jwk' }) as { n: string; e: string };
    const n = Buffer.from(jwk.n, 'base64url');
    const e = Buffer.from(jwk.e, 'base64url');
    return Buffer.concat([Buffer.from([e.length]), e, n]).toString('base64');
}

// add_rsa_key adds a fresh RSA/SHA-256 DNSKEY with flags at apex and
// returns its handler with the private key attached.
function add_rsa_key(zone: DNSSecZone, apex: string, flags: number): DNSKey {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rr = zone.add_rr_from_parts(apex, TTL, 'IN', 'DNSKEY',
        `${flags} ${DNSKEY_PROTOCOL} ${ALGO_RSASHA256} ${rsa_key_b64(publicKey)}`);
    const key = rr.get_handler() as DNSKey;
    key.set_private_key(privateKey);
    return key;
}

// tampered flips one octet of the signature carried by an RRSIG RR.
function tampered(rrsig: ResourceRecord): ResourceRecord {
    const fields = rrsig.value.split(' ');
    const sig = Buffer.from(fields[fields.length - 1], 'base64');
    sig[sig.length >> 1] ^= 0xff;
    const value = [...fields.slice(0, -1), sig.toString('base64')].join(' ');
    return new ResourceRecord(rrsig.label, rrsig.ttl, 'IN', 'RRSIG', value);
}

function sign_with(zone: DNSSecZone, label: string, type: number, key: DNSKey, tamper = false): void {
    const rrsig = zone.sign_rr(label, TTL, type, key, INCEPTION, EXPIRE);
    if (!rrsig) throw new Error(`cannot sign ${label}/${type}`);
    zone.add_rr(tamper ? tampered(rrsig) : rrsig);
}

function make_zone(apex: string, opts: ZoneOptions = {}): ZoneSetup {
    const zone = new DNSSecZone();
    const suffix = apex === '.' ? '.' : '.' + apex;
    zone.add_rr_from_parts(apex, TTL, 'IN', 'SOA',
        `ns1${suffix} admin${suffix} 2021010101 3600 900 604800 86400`);
    const ksk = add_rsa_key(zone, apex, opts.kskFlags ?? FLAGS_KSK);
    sign_with(zone, apex, TYPE_DNSKEY, ksk, opts.tamperDnskeySig ?? false);
    return { apex, zone, ksk };
}

// inject_key adds a new key to setup's DNSKEY rrset and signs the
// modified rrset with it. The real KSK's RRSIG stays in place but no
// longer covers the rrset.
function inject_key(setup: ZoneSetup, flags: number): ZoneSetup {
    const key = add_rsa_key(setup.zone, setup.apex, flags);
    sign_with(setup.zone, setup.apex, TYPE_DNSKEY, key);
    return { ...setup, ksk: key };
}

function ds_value(key: DNSKey): string {
    const digest = crypto.createHash('sha256').update(Buffer.from(key.get_ds_digest_data())).digest();
    return `${key.key_tag} ${key.algorithm} 2 ${digest.toString('hex')}`;
}

// delegate puts a DS for childKey into parent.zone, signed by parent.ksk.
function delegate(parent: ZoneSetup, childApex: string, childKey: DNSKey): void {
    parent.zone.add_rr_from_parts(childApex, TTL, 'IN', 'DS', ds_value(childKey));
    sign_with(parent.zone, childApex, TYPE_DS, parent.ksk);
}

function add_signed(zone: DNSSecZone, label: string, value: string, key: DNSKey): void {
    zone.add_rr_from_parts(label, TTL, 'IN', 'A', value);
    sign_with(zone, label, TYPE_A, key);
}

function trust_anchor_for(key: DNSKey): RootAnchors {
    const digest = crypto.createHash('sha256').update(Buffer.from(key.get_ds_digest_data())).digest();
    return {
        lastUpdated: '2026-01-01',
        source: 'test',
        ds: [{ keyTag: key.key_tag, algorithm: key.algorithm, digestType: 2, digest: digest.toString('hex') }],
        dnskeys: [],
    };
}

class ZoneCollectionResolver implements Resolver {
    constructor(private readonly zones: DNSSecZone[]) {}

    async query(name: string, qtype: number): Promise<{ records: ResourceRecord[]; ad: boolean; rcode: number }> {
        const out: ResourceRecord[] = [];
        for (const z of this.zones) {
            out.push(...z.find_rrset(name, qtype));
            for (const rr of z.find_rrset(name, TYPE_RRSIG)) {
                const h = rr.get_handler();
                if (h instanceof RRSig && h.type_covered === qtype) out.push(rr);
            }
        }
        return { records: out, ad: false, rcode: 0 };
    }
}

async function validate_child(root: ZoneSetup, anchorKey: DNSKey, child: ZoneSetup): Promise<Result> {
    const resolver = new ZoneCollectionResolver([root.zone, child.zone]);
    const v = new Verifier({ resolver, trustAnchors: trust_anchor_for(anchorKey), now: () => NOW });
    return v.validate(CHILD, TYPE_A);
}

// legit_child returns a signed child zone with an A record signed by
// its KSK, delegated from root.
function legit_child(root: ZoneSetup, opts: ZoneOptions = {}): ZoneSetup {
    const child = make_zone(CHILD, opts);
    add_signed(child.zone, CHILD, CHILD_ADDR, child.ksk);
    delegate(root, CHILD, child.ksk);
    return child;
}

//////////////////////////////////////////////////////////// tests

describe('Verifier KSK authentication: baseline', () => {
    it('validates an untouched chain as Secure', async () => {
        const root = make_zone('.');
        const child = legit_child(root);
        const result = await validate_child(root, root.ksk, child);
        expect(result.verdict).toBe(Verdict.Secure);
    });
});

describe('Verifier KSK authentication: tampered KSK signature', () => {
    it('returns Bogus when the child KSK RRSIG over DNSKEY has tampered octets', async () => {
        const root = make_zone('.');
        const child = legit_child(root, { tamperDnskeySig: true });
        const result = await validate_child(root, root.ksk, child);
        expect(result.verdict).toBe(Verdict.Bogus);
        expect(result.bogusAt).toBe(CHILD);
    });

    it('returns Bogus when the root KSK RRSIG over DNSKEY has tampered octets', async () => {
        const root = make_zone('.', { tamperDnskeySig: true });
        const child = legit_child(root);
        const result = await validate_child(root, root.ksk, child);
        expect(result.verdict).toBe(Verdict.Bogus);
        expect(result.bogusAt).toBe('.');
    });
});

describe.each([
    ['SEP-flagged', FLAGS_KSK],
    ['non-SEP', FLAGS_ZSK],
])('Verifier KSK authentication: injected %s key', (_name, flags) => {
    it('returns Bogus when the injected key signs the child DNSKEY rrset and the data', async () => {
        const root = make_zone('.');
        const child = make_zone(CHILD);
        delegate(root, CHILD, child.ksk);
        const attacker = inject_key(child, flags);
        add_signed(child.zone, CHILD, ATTACKER_ADDR, attacker.ksk);

        const result = await validate_child(root, root.ksk, child);
        expect(result.verdict).toBe(Verdict.Bogus);
        expect(result.bogusAt).toBe(CHILD);
        expect(result.answer).toBeUndefined();
    });

    it('returns Bogus when the injected key signs the root DNSKEY rrset and a forged DS', async () => {
        const root = make_zone('.');
        const attacker = inject_key(root, flags);
        const child = make_zone(CHILD);
        add_signed(child.zone, CHILD, ATTACKER_ADDR, child.ksk);
        delegate(attacker, CHILD, child.ksk);

        const result = await validate_child(root, root.ksk, child);
        expect(result.verdict).toBe(Verdict.Bogus);
        expect(result.bogusAt).toBe('.');
        expect(result.answer).toBeUndefined();
    });
});

describe('Verifier KSK authentication: KSK without the SEP flag', () => {
    it('validates a child whose DS-matched KSK lacks the SEP flag as Secure', async () => {
        const root = make_zone('.');
        const child = legit_child(root, { kskFlags: FLAGS_ZSK });
        const result = await validate_child(root, root.ksk, child);
        expect(result.verdict).toBe(Verdict.Secure);
    });

    it('validates a root whose anchor-matched KSK lacks the SEP flag as Secure', async () => {
        const root = make_zone('.', { kskFlags: FLAGS_ZSK });
        const child = legit_child(root);
        const result = await validate_child(root, root.ksk, child);
        expect(result.verdict).toBe(Verdict.Secure);
    });
});

//////////////////////////////////////////////////////////// key-tag collision

interface Ed25519Key {
    raw: Buffer;
    privateKey: crypto.KeyObject;
}

function ed25519_key(): Ed25519Key {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const jwk = publicKey.export({ format: 'jwk' }) as { x: string };
    return { raw: Buffer.from(jwk.x, 'base64url'), privateKey };
}

function tag_of(flags: number, raw: Buffer): number {
    return new DNSKey(null, flags, DNSKEY_PROTOCOL, ALGO_ED25519, new Uint8Array(raw)).key_tag;
}

// colliding_ed25519_keys returns a KSK (flags 257) and a ZSK (flags
// 256) whose key tags are equal.
function colliding_ed25519_keys(): { ksk: Ed25519Key; zsk: Ed25519Key } {
    const kskByTag = new Map<number, Ed25519Key>();
    const zskByTag = new Map<number, Ed25519Key>();
    for (let i = 0; i < MAX_COLLISION_TRIES; i++) {
        const k = ed25519_key();
        const asKsk = tag_of(FLAGS_KSK, k.raw);
        const asZsk = tag_of(FLAGS_ZSK, k.raw);
        const zsk = zskByTag.get(asKsk);
        if (zsk) return { ksk: k, zsk };
        const ksk = kskByTag.get(asZsk);
        if (ksk) return { ksk, zsk: k };
        kskByTag.set(asKsk, k);
        zskByTag.set(asZsk, k);
    }
    throw new Error('no key-tag collision found');
}

function add_ed25519_key(zone: DNSSecZone, apex: string, flags: number, k: Ed25519Key): DNSKey {
    const rr = zone.add_rr_from_parts(apex, TTL, 'IN', 'DNSKEY',
        `${flags} ${DNSKEY_PROTOCOL} ${ALGO_ED25519} ${k.raw.toString('base64')}`);
    const key = rr.get_handler() as DNSKey;
    key.set_private_key(k.privateKey);
    return key;
}

describe('Verifier KSK authentication: key-tag collision', () => {
    it('validates a zone whose KSK shares its key tag with a ZSK listed first', async () => {
        const { ksk: kskPair, zsk: zskPair } = colliding_ed25519_keys();
        const root = make_zone('.');
        const zone = new DNSSecZone();
        zone.add_rr_from_parts(CHILD, TTL, 'IN', 'SOA', 'ns1.example. admin.example. 2021010101 3600 900 604800 86400');
        const zsk = add_ed25519_key(zone, CHILD, FLAGS_ZSK, zskPair);
        const ksk = add_ed25519_key(zone, CHILD, FLAGS_KSK, kskPair);
        expect(zsk.key_tag).toBe(ksk.key_tag);
        sign_with(zone, CHILD, TYPE_DNSKEY, ksk);
        add_signed(zone, CHILD, CHILD_ADDR, ksk);
        delegate(root, CHILD, ksk);

        const result = await validate_child(root, root.ksk, { apex: CHILD, zone, ksk });
        expect(result.verdict).toBe(Verdict.Secure);
    });
});
