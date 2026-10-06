// Shared fixtures for chain-walker tests that build signed zones in
// memory: an RSA/SHA-256 root and child, DS delegation, tampering, and a
// resolver answering from a list of zones (plus optional extra records
// per question, to smuggle data into a specific answer).

import * as crypto from 'crypto';

import { DNSSecZone } from '../../src/dnssec/dnssec_zone';
import { DNSKey, RRSig } from '../../src/dnssec/dnssec_rr';
import { ResourceRecord } from '../../src/zone/dns_zone';
import { StringToRRType } from '../../src/types/dns_type_table';
import { RootAnchors } from '../../src/dnssec/root_anchors';
import { Verifier, VerifierOptions, Resolver, Result } from '../../src/verifier';

export const TYPE_DNSKEY = StringToRRType('DNSKEY');
export const TYPE_DS = StringToRRType('DS');
export const TYPE_RRSIG = StringToRRType('RRSIG');
export const TYPE_A = StringToRRType('A');

export const INCEPTION = 1000000000;
export const EXPIRE    = 2000000000;
export const NOW       = new Date(1500000000 * 1000);
export const TTL       = 3600;

export const FLAGS_KSK = 257;
export const FLAGS_ZSK = 256;
export const ALGO_RSASHA256 = 8;
export const ALGO_ED25519 = 15;
export const DNSKEY_PROTOCOL = 3;

export const CHILD = 'example.';
export const CHILD_ADDR = '192.0.2.1';
export const ATTACKER_ADDR = '198.51.100.66';

export interface ZoneSetup {
    apex: string;
    zone: DNSSecZone;
    ksk: DNSKey;
}

export interface ZoneOptions {
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
export function add_rsa_key(zone: DNSSecZone, apex: string, flags: number): DNSKey {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rr = zone.add_rr_from_parts(apex, TTL, 'IN', 'DNSKEY',
        `${flags} ${DNSKEY_PROTOCOL} ${ALGO_RSASHA256} ${rsa_key_b64(publicKey)}`);
    const key = rr.get_handler() as DNSKey;
    key.set_private_key(privateKey);
    return key;
}

// tampered flips one octet of the signature carried by an RRSIG RR.
export function tampered(rrsig: ResourceRecord): ResourceRecord {
    const fields = rrsig.value.split(' ');
    const sig = Buffer.from(fields[fields.length - 1], 'base64');
    sig[sig.length >> 1] ^= 0xff;
    const value = [...fields.slice(0, -1), sig.toString('base64')].join(' ');
    return new ResourceRecord(rrsig.label, rrsig.ttl, 'IN', 'RRSIG', value);
}

export function sign_with(zone: DNSSecZone, label: string, type: number, key: DNSKey, tamper = false,
                          inception = INCEPTION, expire = EXPIRE): void {
    const rrsig = zone.sign_rr(label, TTL, type, key, inception, expire);
    if (!rrsig) throw new Error(`cannot sign ${label}/${type}`);
    zone.add_rr(tamper ? tampered(rrsig) : rrsig);
}

export function make_zone(apex: string, opts: ZoneOptions = {}): ZoneSetup {
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
export function inject_key(setup: ZoneSetup, flags: number): ZoneSetup {
    const key = add_rsa_key(setup.zone, setup.apex, flags);
    sign_with(setup.zone, setup.apex, TYPE_DNSKEY, key);
    return { ...setup, ksk: key };
}

export function ds_value(key: DNSKey): string {
    const digest = crypto.createHash('sha256').update(Buffer.from(key.get_ds_digest_data())).digest();
    return `${key.key_tag} ${key.algorithm} 2 ${digest.toString('hex')}`;
}

// delegate puts a DS for childKey into parent.zone, signed by parent.ksk.
export function delegate(parent: ZoneSetup, childApex: string, childKey: DNSKey): void {
    parent.zone.add_rr_from_parts(childApex, TTL, 'IN', 'DS', ds_value(childKey));
    sign_with(parent.zone, childApex, TYPE_DS, parent.ksk);
}

export function add_signed(zone: DNSSecZone, label: string, value: string, key: DNSKey): void {
    add_signed_rr(zone, label, 'A', value, key);
}

// add_signed_rr adds (label, type, value) to zone and re-signs the
// rrset with key (an earlier RRSIG over it stays).
export function add_signed_rr(zone: DNSSecZone, label: string, type: string, value: string, key: DNSKey): void {
    const rr = zone.add_rr_from_parts(label, TTL, 'IN', type, value);
    sign_with(zone, label, rr.type, key);
}

// without_rrsigs / rrsigs_only split a response.
export function without_rrsigs(records: ResourceRecord[]): ResourceRecord[] {
    return records.filter((rr) => rr.type !== TYPE_RRSIG);
}

export function rrsigs_only(records: ResourceRecord[]): ResourceRecord[] {
    return records.filter((rr) => rr.type === TYPE_RRSIG);
}

export function trust_anchor_for(key: DNSKey): RootAnchors {
    const digest = crypto.createHash('sha256').update(Buffer.from(key.get_ds_digest_data())).digest();
    return {
        lastUpdated: '2026-01-01',
        source: 'test',
        ds: [{ keyTag: key.key_tag, algorithm: key.algorithm, digestType: 2, digest: digest.toString('hex') }],
        dnskeys: [],
    };
}

// rrset_with_sigs returns the rrset (name, type) of zone followed by the
// RRSIGs covering it.
export function rrset_with_sigs(zone: DNSSecZone, name: string, type: number): ResourceRecord[] {
    const out = [...zone.find_rrset(name, type)];
    for (const rr of zone.find_rrset(name, TYPE_RRSIG)) {
        const h = rr.get_handler();
        if (h instanceof RRSig && h.type_covered === type) out.push(rr);
    }
    return out;
}

// ZoneCollectionResolver answers (name, qtype) with that rrset and its
// RRSIGs from every zone, followed by any extra records registered for
// the question with add_extra. An answer given with set replaces both.
export class ZoneCollectionResolver implements Resolver {
    private readonly extras = new Map<string, ResourceRecord[]>();
    private readonly overrides = new Map<string, ResourceRecord[]>();
    // queries counts the resolver calls.
    queries = 0;

    constructor(private readonly zones: DNSSecZone[]) {}

    add_extra(name: string, qtype: number, records: ResourceRecord[]): void {
        const key = question_key(name, qtype);
        this.extras.set(key, [...(this.extras.get(key) ?? []), ...records]);
    }

    set(name: string, qtype: number, records: ResourceRecord[]): void {
        this.overrides.set(question_key(name, qtype), records);
    }

    answer(name: string, qtype: number): ResourceRecord[] {
        const key = question_key(name, qtype);
        const set = this.overrides.get(key);
        if (set !== undefined) return [...set];
        const out: ResourceRecord[] = [];
        for (const z of this.zones) out.push(...rrset_with_sigs(z, name, qtype));
        out.push(...(this.extras.get(key) ?? []));
        return out;
    }

    async query(name: string, qtype: number): Promise<{ records: ResourceRecord[]; ad: boolean; rcode: number }> {
        this.queries++;
        return { records: this.answer(name, qtype), ad: false, rcode: 0 };
    }
}

function question_key(name: string, qtype: number): string {
    return `${name.toLowerCase()}/${qtype}`;
}

// ThreeLevelChain is root → com. → example.com. with
// www.example.com./A signed by example.com.'s key.
export interface ThreeLevelChain {
    root: ZoneSetup;
    com: ZoneSetup;
    leaf: ZoneSetup;
    resolver: ZoneCollectionResolver;
}

export const LEAF_ZONE = 'example.com.';
export const LEAF_NAME = 'www.example.com.';

export function three_level_chain(): ThreeLevelChain {
    const root = make_zone('.');
    const com = make_zone('com.');
    const leaf = make_zone(LEAF_ZONE);
    delegate(root, 'com.', com.ksk);
    delegate(com, LEAF_ZONE, leaf.ksk);
    add_signed(leaf.zone, LEAF_NAME, CHILD_ADDR, leaf.ksk);
    return { root, com, leaf, resolver: new ZoneCollectionResolver([root.zone, com.zone, leaf.zone]) };
}

export function new_verifier(resolver: Resolver, anchorKey: DNSKey, opts: Partial<VerifierOptions> = {}): Verifier {
    return new Verifier({ resolver, trustAnchors: trust_anchor_for(anchorKey), now: () => NOW, ...opts });
}

export async function validate_child(root: ZoneSetup, anchorKey: DNSKey, child: ZoneSetup): Promise<Result> {
    const resolver = new ZoneCollectionResolver([root.zone, child.zone]);
    return new_verifier(resolver, anchorKey).validate(CHILD, TYPE_A);
}

// legit_child returns a signed child zone with an A record signed by
// its KSK, delegated from root.
export function legit_child(root: ZoneSetup, opts: ZoneOptions = {}): ZoneSetup {
    const child = make_zone(CHILD, opts);
    add_signed(child.zone, CHILD, CHILD_ADDR, child.ksk);
    delegate(root, CHILD, child.ksk);
    return child;
}
