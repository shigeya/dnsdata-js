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
import { DNSKey } from '../../src/dnssec/dnssec_rr';
import { Verdict } from '../../src/verifier';
import {
    ALGO_ED25519, ATTACKER_ADDR, CHILD, CHILD_ADDR, DNSKEY_PROTOCOL, FLAGS_KSK, FLAGS_ZSK, TTL, TYPE_DNSKEY,
    add_signed, delegate, inject_key, legit_child, make_zone, sign_with, validate_child,
} from './key_auth_fixtures';

const MAX_COLLISION_TRIES = 20000;

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
