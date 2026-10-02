// Answer shapes seen from real servers (UF-007 in dnsdata-go).
// Ports dnsdata-go `verifier/alias_shapes_test.go` and
// `verifier/negative_shapes_test.go`:
//
//   - a DNAME answer carries the CNAME synthesised from it, which has
//     no RRSIG (RFC 6672 §5.3.1);
//   - a recursive resolver puts the alias target's RRset into the same
//     answer;
//   - wildcard NODATA (RFC 4035 §3.1.3.4, RFC 5155 §7.2.5) and empty
//     non-terminal NODATA are NOERROR answers and must not be
//     classified as NXDOMAIN.

import * as crypto from 'crypto';

import { DNSSecZone } from '../../src/dnssec/dnssec_zone';
import { DNSKey, DNSRR_NSEC3, RRSig } from '../../src/dnssec/dnssec_rr';
import { ResourceRecord } from '../../src/zone/dns_zone';
import { StringToRRType } from '../../src/types/dns_type_table';
import { RootAnchors } from '../../src/dnssec/root_anchors';
import { Verifier, Verdict, Resolver } from '../../src/verifier';
import { Result } from '../../src/verifier/result';

const T = (name: string): number => StringToRRType(name);
const TYPE_RRSIG = T('RRSIG');

const INCEPTION = 1000000000;
const EXPIRE    = 2000000000;
const NOW       = new Date(1500000000 * 1000);

//////////////////////////////////////////////////////////// fixtures

interface ZoneSetup {
    apex: string;
    zone: DNSSecZone;
    ksk: DNSKey;
}

function make_zone(apex: string): ZoneSetup {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = publicKey.export({ format: 'jwk' }) as { n: string; e: string };
    const n = Buffer.from(jwk.n, 'base64url');
    const e = Buffer.from(jwk.e, 'base64url');
    const keyB64 = Buffer.concat([Buffer.from([e.length]), e, n]).toString('base64');

    const zone = new DNSSecZone();
    zone.add_rr_from_parts(apex, 3600, 'IN', 'DNSKEY', `257 3 8 ${keyB64}`);
    const ksk = zone.find_rr(apex, T('DNSKEY'))!.get_handler() as DNSKey;
    ksk.set_private_key(privateKey);
    const setup = { apex, zone, ksk };
    sign(setup, apex, 'DNSKEY');
    return setup;
}

function sign(setup: ZoneSetup, owner: string, type: string): void {
    const rrsig = setup.zone.sign_rr(owner, 3600, T(type), setup.ksk, INCEPTION, EXPIRE);
    if (rrsig) setup.zone.add_rr(rrsig);
}

function add_signed(setup: ZoneSetup, owner: string, type: string, value: string): void {
    setup.zone.add_rr_from_parts(owner, 3600, 'IN', type, value);
    sign(setup, owner, type);
}

function ds_digest(ksk: DNSKey): string {
    return crypto.createHash('sha256').update(Buffer.from(ksk.get_ds_digest_data())).digest('hex');
}

function delegate(parent: ZoneSetup, child: ZoneSetup): void {
    add_signed(parent, child.apex, 'DS', `${child.ksk.key_tag} ${child.ksk.algorithm} 2 ${ds_digest(child.ksk)}`);
}

function trust_anchor_for(setup: ZoneSetup): RootAnchors {
    return {
        lastUpdated: '2026-01-01',
        source: 'test',
        ds: [{ keyTag: setup.ksk.key_tag, algorithm: setup.ksk.algorithm, digestType: 2, digest: ds_digest(setup.ksk) }],
        dnskeys: [],
    };
}

// with_sigs returns z's records at (name, type) and the RRSIGs at
// name covering type.
function with_sigs(z: DNSSecZone, name: string, type: number): ResourceRecord[] {
    const out = [...z.find_rrset(name, type)];
    for (const rr of z.find_rrset(name, TYPE_RRSIG)) {
        const h = rr.get_handler();
        if (h instanceof RRSig && h.type_covered === type) out.push(rr);
    }
    return out;
}

// unsigned_rr builds a record with no RRSIG, the way a server
// synthesises a CNAME from a DNAME.
function unsigned_rr(owner: string, type: string, value: string): ResourceRecord {
    const scratch = new DNSSecZone();
    scratch.add_rr_from_parts(owner, 300, 'IN', type, value);
    return scratch.find_rr(owner, T(type))!;
}

class MapResolver implements Resolver {
    private readonly map = new Map<string, ResourceRecord[]>();

    set(name: string, qtype: number, records: ResourceRecord[]): void {
        this.map.set(`${name} ${qtype}`, records);
    }

    async query(name: string, qtype: number): Promise<{ records: ResourceRecord[]; ad: boolean; rcode: number }> {
        return { records: this.map.get(`${name} ${qtype}`) ?? [], ad: false, rcode: 0 };
    }
}

// TwoBranchChain is a signed tree with two leaf zones under different
// TLDs, so an alias can cross from example.com. to example.net.:
//
//   .  ─┬─ com. ── example.com.
//       └─ net. ── example.net.
class TwoBranchChain {
    readonly root = make_zone('.');
    readonly com = make_zone('com.');
    readonly net = make_zone('net.');
    readonly src = make_zone('example.com.');
    readonly dst = make_zone('example.net.');
    readonly resolver = new MapResolver();

    constructor() {
        const cuts: [ZoneSetup, ZoneSetup][] = [
            [this.root, this.com], [this.root, this.net], [this.com, this.src], [this.net, this.dst],
        ];
        this.resolver.set('.', T('DNSKEY'), with_sigs(this.root.zone, '.', T('DNSKEY')));
        for (const [parent, child] of cuts) {
            delegate(parent, child);
            this.resolver.set(child.apex, T('DS'), with_sigs(parent.zone, child.apex, T('DS')));
            this.resolver.set(child.apex, T('DNSKEY'), with_sigs(child.zone, child.apex, T('DNSKEY')));
        }
    }

    validate(qname: string, qtype: number): Promise<Result> {
        const v = new Verifier({ resolver: this.resolver, trustAnchors: trust_anchor_for(this.root), now: () => NOW });
        return v.validate(qname, qtype);
    }
}

function expect_secure_alias(res: Result, type: string, from: string, target: string, qtype: number): void {
    expect(`${res.verdict} ${res.bogusReason ?? ''}`.trim()).toBe(Verdict.Secure);
    expect(res.aliases?.map(a => `${a.type} ${a.from} ${a.target}`)).toEqual([`${type} ${from} ${target}`]);
    expect(res.answer?.name).toBe(target);
    expect(res.answer?.type).toBe(qtype);
}

// dname_at_apex puts "example.com. DNAME example.net." and a TXT at the
// rewritten name, and returns what an authoritative server for
// example.com. sends for www.example.com.: the signed DNAME plus the
// unsigned CNAME it synthesised.
function dname_at_apex(c: TwoBranchChain): ResourceRecord[] {
    add_signed(c.src, 'example.com.', 'DNAME', 'example.net.');
    add_signed(c.dst, 'www.example.net.', 'TXT', '"hello"');
    return [
        ...with_sigs(c.src.zone, 'example.com.', T('DNAME')),
        unsigned_rr('www.example.com.', 'CNAME', 'www.example.net.'),
    ];
}

//////////////////////////////////////////////////////////// aliases

describe('Verifier alias answer shapes', () => {
    it('validates a DNAME answer that carries the synthesised CNAME', async () => {
        const c = new TwoBranchChain();
        const answer = dname_at_apex(c);
        c.resolver.set('www.example.com.', T('TXT'), answer);
        c.resolver.set('www.example.com.', T('DS'), answer);
        c.resolver.set('www.example.net.', T('TXT'), with_sigs(c.dst.zone, 'www.example.net.', T('TXT')));

        // from is the DNAME owner, not the queried name.
        expect_secure_alias(await c.validate('www.example.com.', T('TXT')), 'dname', 'example.com.', 'www.example.net.', T('TXT'));
    });

    it('validates a DNAME answer from a recursive resolver (target RRset included)', async () => {
        const c = new TwoBranchChain();
        const answer = dname_at_apex(c);
        const target = with_sigs(c.dst.zone, 'www.example.net.', T('TXT'));
        c.resolver.set('www.example.com.', T('TXT'), [...answer, ...target]);
        c.resolver.set('www.example.net.', T('TXT'), target);

        expect_secure_alias(await c.validate('www.example.com.', T('TXT')), 'dname', 'example.com.', 'www.example.net.', T('TXT'));
    });

    it('validates a CNAME answer from a recursive resolver (target RRset included)', async () => {
        const c = new TwoBranchChain();
        add_signed(c.src, 'www.example.com.', 'CNAME', 'host.example.net.');
        add_signed(c.dst, 'host.example.net.', 'TXT', '"hello"');
        const target = with_sigs(c.dst.zone, 'host.example.net.', T('TXT'));
        c.resolver.set('www.example.com.', T('TXT'), [...with_sigs(c.src.zone, 'www.example.com.', T('CNAME')), ...target]);
        c.resolver.set('host.example.net.', T('TXT'), target);

        expect_secure_alias(await c.validate('www.example.com.', T('TXT')), 'cname', 'www.example.com.', 'host.example.net.', T('TXT'));
    });

    it('keeps an unsigned CNAME without a DNAME above it Bogus', async () => {
        const c = new TwoBranchChain();
        add_signed(c.dst, 'www.example.net.', 'TXT', '"hello"');
        c.resolver.set('www.example.com.', T('TXT'), [unsigned_rr('www.example.com.', 'CNAME', 'www.example.net.')]);
        c.resolver.set('www.example.net.', T('TXT'), with_sigs(c.dst.zone, 'www.example.net.', T('TXT')));

        expect((await c.validate('www.example.com.', T('TXT'))).verdict).toBe(Verdict.Bogus);
    });
});

//////////////////////////////////////////////////////////// NSEC NODATA

describe('Verifier NODATA shapes (NSEC)', () => {
    it('proves wildcard NODATA with one NSEC that covers qname and matches the wildcard', async () => {
        const c = new TwoBranchChain();
        add_signed(c.src, '*.example.com.', 'NSEC', 'example.com. TXT RRSIG NSEC');
        c.resolver.set('foo.bar.example.com.', T('A'), with_sigs(c.src.zone, '*.example.com.', T('NSEC')));

        const res = await c.validate('foo.bar.example.com.', T('A'));
        expect(`${res.verdict} ${res.negativeReason ?? ''}`).toMatch(/^secure-nodata .*wildcard/);
    });

    it('returns no negative verdict when the wildcard owns the asked type', async () => {
        const c = new TwoBranchChain();
        add_signed(c.src, '*.example.com.', 'NSEC', 'example.com. A TXT RRSIG NSEC');
        c.resolver.set('foo.example.com.', T('A'), with_sigs(c.src.zone, '*.example.com.', T('NSEC')));

        const res = await c.validate('foo.example.com.', T('A'));
        expect([Verdict.SecureNoData, Verdict.SecureNXDomain]).not.toContain(res.verdict);
    });

    it('proves NODATA at an empty non-terminal', async () => {
        const c = new TwoBranchChain();
        add_signed(c.src, 'example.com.', 'NSEC', 'a.b.example.com. NS SOA RRSIG NSEC DNSKEY');
        c.resolver.set('b.example.com.', T('A'), with_sigs(c.src.zone, 'example.com.', T('NSEC')));

        const res = await c.validate('b.example.com.', T('A'));
        expect(`${res.verdict} ${res.negativeReason ?? ''}`).toMatch(/^secure-nodata .*empty non-terminal/);
    });
});

//////////////////////////////////////////////////////////// NSEC3 NODATA

const BASE32HEX = '0123456789ABCDEFGHIJKLMNOPQRSTUV';

function base32hex(bytes: Uint8Array): string {
    let out = '';
    let bits = 0;
    let acc = 0;
    for (const b of bytes) {
        acc = ((acc << 8) | b) & 0xffff;
        bits += 8;
        while (bits >= 5) {
            out += BASE32HEX[(acc >> (bits - 5)) & 0x1f];
            bits -= 5;
        }
    }
    if (bits > 0) out += BASE32HEX[(acc << (5 - bits)) & 0x1f];
    return out;
}

function nsec3_hash(name: string): Uint8Array {
    return DNSRR_NSEC3.compute_hash(name, 1, 0, new Uint8Array(0));
}

function bump(hash: Uint8Array, delta: number): Uint8Array {
    const out = Uint8Array.from(hash);
    out[out.length - 1] = (out[out.length - 1] + delta) & 0xff;
    return out;
}

function add_nsec3(c: TwoBranchChain, owner: Uint8Array, next: Uint8Array, types: string): string {
    const name = `${base32hex(owner)}.example.com.`;
    add_signed(c.src, name, 'NSEC3', `1 0 0 - ${base32hex(next)} ${types}`);
    return name;
}

// wildcard_nsec3_answer builds the RFC 5155 §7.2.5 shape for
// foo.bar.example.com.: an NSEC3 matching the closest encloser
// example.com., one covering the next closer bar.example.com., and one
// matching *.example.com. with wildcardTypes.
function wildcard_nsec3_answer(c: TwoBranchChain, wildcardTypes: string): ResourceRecord[] {
    const ce = nsec3_hash('example.com.');
    const nc = nsec3_hash('bar.example.com.');
    const wc = nsec3_hash('*.example.com.');
    const owners = [
        add_nsec3(c, ce, bump(ce, 1), 'NS SOA RRSIG DNSKEY NSEC3PARAM'),
        add_nsec3(c, bump(nc, -1), bump(nc, 1), 'TXT RRSIG'),
        add_nsec3(c, wc, bump(wc, 1), wildcardTypes),
    ];
    return owners.flatMap(o => with_sigs(c.src.zone, o, T('NSEC3')));
}

describe('Verifier NODATA shapes (NSEC3)', () => {
    it('proves wildcard NODATA', async () => {
        const c = new TwoBranchChain();
        c.resolver.set('foo.bar.example.com.', T('A'), wildcard_nsec3_answer(c, 'TXT RRSIG'));

        const res = await c.validate('foo.bar.example.com.', T('A'));
        expect(`${res.verdict} ${res.negativeReason ?? ''}`).toMatch(/^secure-nodata .*wildcard/);
    });

    it('returns no negative verdict when the wildcard owns the asked type', async () => {
        const c = new TwoBranchChain();
        c.resolver.set('foo.bar.example.com.', T('A'), wildcard_nsec3_answer(c, 'A TXT RRSIG'));

        const res = await c.validate('foo.bar.example.com.', T('A'));
        expect([Verdict.SecureNoData, Verdict.SecureNXDomain]).not.toContain(res.verdict);
    });
});
