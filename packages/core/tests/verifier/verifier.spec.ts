// Verifier tests
//
// Builds in-memory signed zones, threads them through a mock
// Resolver, and asserts the chain walker reaches the expected
// verdict. The interesting fixture is the `.jp.` shape (#5 / UP-001
// from dnsdata-go) where `ad.jp.` is an empty non-terminal between
// two real zone cuts — a naive descent loop that exits on the first
// no-DS response will leaf-resolve under the wrong zone's keys.

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
    VerifierConfigError,
    VerifierInvalidQNameError,
    VerifierResolverError,
    VerifierChainTimeoutError,
    descendant_zones,
    normalize_qname,
    combine_verdicts,
    synthesise_dname_target,
    MAX_ALIAS_HOPS,
} from '../../src/verifier';

const TYPE_DNSKEY = StringToRRType('DNSKEY');
const TYPE_DS = StringToRRType('DS');
const TYPE_RRSIG = StringToRRType('RRSIG');
const TYPE_A = StringToRRType('A');

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
    const apexLabel = apex === '.' ? '.' : apex;
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

// Add a DS for child.apex into parent.zone and sign it with parent.ksk.
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

function trust_anchor_for(setup: ZoneSetup, digestType = 2): RootAnchors {
    const dsInput = setup.ksk.get_ds_digest_data();
    const algo = digestType === 1 ? 'sha1' : digestType === 4 ? 'sha384' : 'sha256';
    const dsHash = crypto.createHash(algo).update(Buffer.from(dsInput)).digest();
    return {
        lastUpdated: '2026-01-01',
        source: 'test',
        ds: [{
            keyTag: setup.ksk.key_tag,
            algorithm: setup.ksk.algorithm,
            digestType,
            digest: dsHash.toString('hex'),
        }],
        dnskeys: [],
    };
}

// Resolver backed by a list of signed in-memory zones. For each
// query it scans every zone, gathering records whose owner equals
// `name` and type equals `qtype`, plus any RRSIG at the same name
// covering qtype. This mirrors real DNS where DS sits in the parent
// zone while DNSKEY/A/etc. sit in the child zone — every name lives
// in exactly one authoritative zone for a given type, so a flat
// scan never produces duplicates.
class ZoneCollectionResolver implements Resolver {
    public queries: { name: string; qtype: number }[] = [];

    constructor(private readonly zones: DNSSecZone[]) {}

    async query(name: string, qtype: number): Promise<{ records: ResourceRecord[]; ad: boolean; rcode: number }> {
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
        return { records: out, ad: false, rcode: 0 };
    }
}

//////////////////////////////////////////////////////////// unit tests

describe('descendant_zones', () => {
    it('returns empty for root', () => {
        expect(descendant_zones('.')).toEqual([]);
    });

    it('orders shallowest-first and includes qname', () => {
        expect(descendant_zones('www.example.com.')).toEqual([
            'com.',
            'example.com.',
            'www.example.com.',
        ]);
    });

    it('lowercases and ensures trailing dot', () => {
        expect(descendant_zones('WWW.Example.COM')).toEqual([
            'com.',
            'example.com.',
            'www.example.com.',
        ]);
    });

    it('handles the empty-non-terminal shape', () => {
        // The fix in #5 hinges on this case: "ad.jp." sits between
        // "jp." (cut) and "wide.ad.jp." (cut) and must NOT be the
        // place the descent loop bails out.
        expect(descendant_zones('sfc.wide.ad.jp.')).toEqual([
            'jp.',
            'ad.jp.',
            'wide.ad.jp.',
            'sfc.wide.ad.jp.',
        ]);
    });
});

describe('normalize_qname', () => {
    it('preserves a normalised name', () => {
        expect(normalize_qname('example.com.')).toBe('example.com.');
    });
    it('lower-cases and appends trailing dot', () => {
        expect(normalize_qname('Example.COM')).toBe('example.com.');
    });
    it('returns root for empty', () => {
        expect(normalize_qname('')).toBe('.');
    });
});

describe('Verifier construction', () => {
    it('throws VerifierConfigError when resolver missing', () => {
        // Cast to bypass the compile-time required field — verifying
        // the runtime guard for callers passing dynamic options.
        expect(() => new Verifier({} as unknown as { resolver: Resolver }))
            .toThrow(VerifierConfigError);
    });
});

describe('Verifier.validate input handling', () => {
    it('rejects empty qname', async () => {
        const resolver: Resolver = { async query() { return { records: [], ad: false, rcode: 0 }; } };
        const v = new Verifier({ resolver });
        await expect(v.validate('', TYPE_A)).rejects.toBeInstanceOf(VerifierInvalidQNameError);
    });

    it('wraps resolver errors in VerifierResolverError', async () => {
        const resolver: Resolver = {
            async query() { throw new Error('network down'); },
        };
        const v = new Verifier({ resolver });
        await expect(v.validate('example.com.', TYPE_A))
            .rejects.toBeInstanceOf(VerifierResolverError);
    });

    it('honours AbortSignal before querying', async () => {
        const resolver: Resolver = { async query() { return { records: [], ad: false, rcode: 0 }; } };
        const v = new Verifier({ resolver });
        const ctrl = new AbortController();
        ctrl.abort();
        await expect(v.validate('example.com.', TYPE_A, ctrl.signal))
            .rejects.toBeInstanceOf(VerifierChainTimeoutError);
    });
});

//////////////////////////////////////////////////////////// chain walks

describe('Verifier chain walk', () => {
    it('returns Bogus when root KSK does not match trust anchors', async () => {
        const root = make_zone('.');
        const resolver = new ZoneCollectionResolver([root.zone]);
        const bogusAnchors: RootAnchors = {
            lastUpdated: '2026-01-01',
            source: 'test',
            ds: [{ keyTag: 0, algorithm: 8, digestType: 2, digest: '00'.repeat(32) }],
            dnskeys: [],
        };
        const v = new Verifier({ resolver, trustAnchors: bogusAnchors });
        const result = await v.validate('example.', TYPE_A);
        expect(result.verdict).toBe(Verdict.Bogus);
        expect(result.bogusAt).toBe('.');
        expect(result.bogusReason).toMatch(/trust anchor/);
    });

    it('returns Secure for a one-deep empty-non-terminal chain (wide.ad.jp.)', async () => {
        // Chain shape: root → jp. (signed cut) → ad.jp. (NOT a cut,
        // empty non-terminal) → wide.ad.jp. (signed cut). The leaf
        // rrset lives at the wide.ad.jp. apex.
        const root = make_zone('.');
        const jp = make_zone('jp.');
        const wideAdJp = make_zone('wide.ad.jp.');

        delegate(root, jp);
        delegate(jp, wideAdJp);

        add_signed(wideAdJp, 'wide.ad.jp.', 'A', '203.178.136.36');

        const resolver = new ZoneCollectionResolver([root.zone, jp.zone, wideAdJp.zone]);
        const v = new Verifier({ resolver, trustAnchors: trust_anchor_for(root) });

        const result = await v.validate('wide.ad.jp.', TYPE_A);
        expect(result.verdict).toBe(Verdict.Secure);

        // Chain should record three zones (root, jp., wide.ad.jp.) —
        // ad.jp. is correctly skipped because it isn't a cut.
        expect(result.chain.map(s => s.zone)).toEqual(['.', 'jp.', 'wide.ad.jp.']);
        for (const step of result.chain) {
            expect(step.signedBy).toBeDefined();
        }

        // Evidence accumulated along the way.
        expect(result.evidence.dnskeys['.']?.length).toBeGreaterThan(0);
        expect(result.evidence.dnskeys['jp.']?.length).toBeGreaterThan(0);
        expect(result.evidence.dnskeys['wide.ad.jp.']?.length).toBeGreaterThan(0);
        expect(result.evidence.dses['jp.']?.length).toBeGreaterThan(0);
        expect(result.evidence.dses['wide.ad.jp.']?.length).toBeGreaterThan(0);
    });

    it('returns Secure for a two-deep empty-non-terminal chain (sfc.wide.ad.jp.)', async () => {
        // Same shape as above but the leaf is one cut deeper, so the
        // descent loop also has to `continue` past sfc.wide.ad.jp.
        // (not a cut — just a leaf record name).
        const root = make_zone('.');
        const jp = make_zone('jp.');
        const wideAdJp = make_zone('wide.ad.jp.');

        delegate(root, jp);
        delegate(jp, wideAdJp);

        add_signed(wideAdJp, 'sfc.wide.ad.jp.', 'A', '203.178.137.5');

        const resolver = new ZoneCollectionResolver([root.zone, jp.zone, wideAdJp.zone]);
        const v = new Verifier({ resolver, trustAnchors: trust_anchor_for(root) });

        const result = await v.validate('sfc.wide.ad.jp.', TYPE_A);
        expect(result.verdict).toBe(Verdict.Secure);
        expect(result.chain.map(s => s.zone)).toEqual(['.', 'jp.', 'wide.ad.jp.']);

        // The resolver MUST have been asked for DS at the empty
        // non-terminal `ad.jp.` (parent returned nothing → continue)
        // AND for DS at the non-cut leaf parent `sfc.wide.ad.jp.`
        // (same — empty, continue), then for A at sfc.wide.ad.jp.
        const dsQueries = resolver.queries.filter(q => q.qtype === TYPE_DS).map(q => q.name);
        expect(dsQueries).toEqual(expect.arrayContaining(['jp.', 'ad.jp.', 'wide.ad.jp.', 'sfc.wide.ad.jp.']));
    });

    it('returns Bogus when a leaf RRSIG does not verify', async () => {
        // Tamper with the leaf A record's RRSIG so signature
        // validation fails at the deepest cut.
        const root = make_zone('.');
        const example = make_zone('example.');
        delegate(root, example);

        add_signed(example, 'host.example.', 'A', '192.0.2.1');

        // Add a competing RRSIG with a garbage signature for the
        // same key_tag — the legitimate RRSIG still exists so this
        // alone would not flip the verdict. Then drop the legitimate
        // one.
        const legitSig = example.zone.find_rrset('host.example.', TYPE_RRSIG)[0];
        expect(legitSig).toBeDefined();
        const rrsigHandler = legitSig.get_handler() as RRSig;
        const garbageB64 = Buffer.alloc(rrsigHandler.signature.length).toString('base64');
        const tamperedValue = `A ${rrsigHandler.algorithm} ${rrsigHandler.labels} 3600 ${rrsigHandler.expire} ${rrsigHandler.inception} ${rrsigHandler.key_tag} ${rrsigHandler.signer} ${garbageB64}`;

        // Replace the RRSIG list with just the tampered one.
        const tamperedZone = example.zone as unknown as { records: Map<string, ResourceRecord[]> };
        const rrsigKey = `host.example.\0${TYPE_RRSIG}`;
        tamperedZone.records.set(rrsigKey, [new ResourceRecord('host.example.', 3600, 'IN', 'RRSIG', tamperedValue)]);

        const resolver = new ZoneCollectionResolver([root.zone, example.zone]);
        const v = new Verifier({ resolver, trustAnchors: trust_anchor_for(root) });

        const result = await v.validate('host.example.', TYPE_A);
        expect(result.verdict).toBe(Verdict.Bogus);
        expect(result.bogusReason).toMatch(/RRSIG/);
    });

    it('returns Indeterminate when the leaf rrset is missing and no NSEC/NSEC3 proof is supplied', async () => {
        const root = make_zone('.');
        const example = make_zone('example.');
        delegate(root, example);
        // No A record added at host.example. → resolver returns
        // empty.
        const resolver = new ZoneCollectionResolver([root.zone, example.zone]);
        const v = new Verifier({ resolver, trustAnchors: trust_anchor_for(root) });

        const result = await v.validate('host.example.', TYPE_A);
        expect(result.verdict).toBe(Verdict.Indeterminate);
        // Chain still walks all the way down to example.
        expect(result.chain.map(s => s.zone)).toEqual(['.', 'example.']);
    });
});

//////////////////////////////////////////////////////////// negative proofs

describe('Verifier negative proofs (UP-004 / #8)', () => {
    it('returns Insecure when the parent proves no-DS via a matching NSEC', async () => {
        // Two-level chain: root → com. is signed; example.com. has no
        // DS in com. — and com. publishes an NSEC at example.com. with
        // a no-DS bitmap (NS RRSIG NSEC, no DS / SOA).
        const root = make_zone('.');
        const com = make_zone('com.');
        delegate(root, com);

        add_signed(com, 'example.com.', 'NSEC', 'f.com. NS RRSIG NSEC');

        const resolver = new MapResolver([
            [key('.', TYPE_DNSKEY), find_with_sigs(root.zone, '.', TYPE_DNSKEY)],
            [key('com.', TYPE_DS), find_with_sigs(root.zone, 'com.', TYPE_DS)],
            [key('com.', TYPE_DNSKEY), find_with_sigs(com.zone, 'com.', TYPE_DNSKEY)],
            // DS at example.com. → empty + signed NSEC proving no-DS.
            [key('example.com.', TYPE_DS), find_with_sigs(com.zone, 'example.com.', TYPE_NSEC)],
        ]);
        const v = new Verifier({ resolver, trustAnchors: trust_anchor_for(root) });

        const result = await v.validate('www.example.com.', TYPE_A);
        expect(result.verdict).toBe(Verdict.Insecure);
        expect(result.insecureAt).toBe('example.com.');
        expect(result.insecureReason).toMatch(/NSEC/);
    });

    it('does NOT classify Insecure when the NSEC bitmap also contains DS', async () => {
        // Same shape, but the NSEC asserts a DS bit — contradicting
        // the missing DS rrset. The proof MUST NOT be accepted, so
        // the verdict falls through to Indeterminate (the chain walker
        // continues past example.com. as a non-cut and the DNSKEY
        // lookup at host.example.com. eventually returns nothing).
        const root = make_zone('.');
        const com = make_zone('com.');
        delegate(root, com);

        add_signed(com, 'example.com.', 'NSEC', 'f.com. NS DS RRSIG NSEC');

        const resolver = new MapResolver([
            [key('.', TYPE_DNSKEY), find_with_sigs(root.zone, '.', TYPE_DNSKEY)],
            [key('com.', TYPE_DS), find_with_sigs(root.zone, 'com.', TYPE_DS)],
            [key('com.', TYPE_DNSKEY), find_with_sigs(com.zone, 'com.', TYPE_DNSKEY)],
            [key('example.com.', TYPE_DS), find_with_sigs(com.zone, 'example.com.', TYPE_NSEC)],
            // Empty leaf responses → fall through to Indeterminate.
            [key('host.example.com.', TYPE_DS), []],
            [key('host.example.com.', TYPE_A), []],
        ]);
        const v = new Verifier({ resolver, trustAnchors: trust_anchor_for(root) });

        const result = await v.validate('host.example.com.', TYPE_A);
        expect(result.verdict).not.toBe(Verdict.Insecure);
    });

    it('returns SecureNoData when the leaf zone proves NODATA via a matching NSEC', async () => {
        // Three-level chain: root → com. → example.com. is fully
        // signed. www.example.com. has an A record AND an NSEC saying
        // "I have A RRSIG NSEC, nothing else." Asking for AAAA should
        // produce a SecureNoData verdict.
        const root = make_zone('.');
        const com = make_zone('com.');
        const example = make_zone('example.com.');
        delegate(root, com);
        delegate(com, example);

        add_signed(example, 'www.example.com.', 'A', '192.0.2.1');
        add_signed(example, 'www.example.com.', 'NSEC', 'z.example.com. A RRSIG NSEC');

        const resolver = new MapResolver([
            [key('.', TYPE_DNSKEY), find_with_sigs(root.zone, '.', TYPE_DNSKEY)],
            [key('com.', TYPE_DS), find_with_sigs(root.zone, 'com.', TYPE_DS)],
            [key('com.', TYPE_DNSKEY), find_with_sigs(com.zone, 'com.', TYPE_DNSKEY)],
            [key('example.com.', TYPE_DS), find_with_sigs(com.zone, 'example.com.', TYPE_DS)],
            [key('example.com.', TYPE_DNSKEY), find_with_sigs(example.zone, 'example.com.', TYPE_DNSKEY)],
            [key('www.example.com.', TYPE_DS), []],
            // AAAA → empty, but the NSEC at www.example.com. is the
            // NODATA proof.
            [key('www.example.com.', StringToRRType('AAAA')), find_with_sigs(example.zone, 'www.example.com.', TYPE_NSEC)],
        ]);
        const v = new Verifier({ resolver, trustAnchors: trust_anchor_for(root) });

        const result = await v.validate('www.example.com.', StringToRRType('AAAA'));
        expect(result.verdict).toBe(Verdict.SecureNoData);
        expect(result.negativeReason).toMatch(/NSEC/);
    });

    it('returns SecureNXDomain when two NSECs cover qname and the wildcard', async () => {
        // Two NSECs at the leaf zone:
        //   apex NSEC: example.com. → m.example.com.  (covers *.example.com.)
        //   later NSEC: m.example.com. → z.example.com.  (covers missing.example.com.)
        // Together they prove qname does not exist AND no wildcard exists.
        const root = make_zone('.');
        const com = make_zone('com.');
        const example = make_zone('example.com.');
        delegate(root, com);
        delegate(com, example);

        add_signed(example, 'example.com.', 'NSEC', 'm.example.com. NS SOA RRSIG NSEC');
        add_signed(example, 'm.example.com.', 'NSEC', 'z.example.com. A RRSIG NSEC');

        const nsecs = [
            ...find_with_sigs(example.zone, 'example.com.', TYPE_NSEC),
            ...find_with_sigs(example.zone, 'm.example.com.', TYPE_NSEC),
        ];

        const resolver = new MapResolver([
            [key('.', TYPE_DNSKEY), find_with_sigs(root.zone, '.', TYPE_DNSKEY)],
            [key('com.', TYPE_DS), find_with_sigs(root.zone, 'com.', TYPE_DS)],
            [key('com.', TYPE_DNSKEY), find_with_sigs(com.zone, 'com.', TYPE_DNSKEY)],
            [key('example.com.', TYPE_DS), find_with_sigs(com.zone, 'example.com.', TYPE_DS)],
            [key('example.com.', TYPE_DNSKEY), find_with_sigs(example.zone, 'example.com.', TYPE_DNSKEY)],
            [key('missing.example.com.', TYPE_DS), []],
            [key('missing.example.com.', TYPE_A), nsecs],
        ]);
        const v = new Verifier({ resolver, trustAnchors: trust_anchor_for(root) });

        const result = await v.validate('missing.example.com.', TYPE_A);
        expect(result.verdict).toBe(Verdict.SecureNXDomain);
        expect(result.negativeReason).toMatch(/wildcard/);
    });
});

const TYPE_NSEC = StringToRRType('NSEC');

// MapResolver answers from an explicit (name, qtype) → records lookup
// table. Used by the negative-proof tests because those need precise
// control over which records appear in which response — e.g. a "DS at
// example.com." query that returns an NSEC instead of a DS rrset.
class MapResolver implements Resolver {
    private readonly map = new Map<string, ResourceRecord[]>();
    public queries: { name: string; qtype: number }[] = [];

    constructor(entries: [string, ResourceRecord[]][]) {
        for (const [k, rs] of entries) this.map.set(k, rs);
    }

    async query(name: string, qtype: number): Promise<{ records: ResourceRecord[]; ad: boolean; rcode: number }> {
        this.queries.push({ name, qtype });
        return { records: this.map.get(key(name, qtype)) ?? [], ad: false, rcode: 0 };
    }
}

function key(name: string, qtype: number): string {
    return `${name} ${qtype}`;
}

// find_with_sigs returns z's records at (name, qtype) together with
// any RRSIG at the same name covering qtype. Mirrors the rrsetWithSigs
// helper in the Go test suite.
function find_with_sigs(z: DNSSecZone, name: string, qtype: number): ResourceRecord[] {
    const out: ResourceRecord[] = [];
    out.push(...z.find_rrset(name, qtype));
    for (const rr of z.find_rrset(name, TYPE_RRSIG)) {
        const h = rr.get_handler();
        if (h instanceof RRSig && h.type_covered === qtype) {
            out.push(rr);
        }
    }
    return out;
}

//////////////////////////////////////////////////////////// alias chasing

const TYPE_CNAME = StringToRRType('CNAME');
const TYPE_DNAME = StringToRRType('DNAME');

describe('combine_verdicts', () => {
    it('Bogus dominates everything', () => {
        for (const v of [Verdict.Indeterminate, Verdict.Secure, Verdict.SecureNoData, Verdict.SecureNXDomain, Verdict.Insecure, Verdict.Bogus]) {
            expect(combine_verdicts(Verdict.Bogus, v)).toBe(Verdict.Bogus);
            expect(combine_verdicts(v, Verdict.Bogus)).toBe(Verdict.Bogus);
        }
    });

    it('Insecure beats Indeterminate and Secure flavours', () => {
        expect(combine_verdicts(Verdict.Insecure, Verdict.Secure)).toBe(Verdict.Insecure);
        expect(combine_verdicts(Verdict.Insecure, Verdict.SecureNoData)).toBe(Verdict.Insecure);
        expect(combine_verdicts(Verdict.Indeterminate, Verdict.Insecure)).toBe(Verdict.Insecure);
    });

    it('Indeterminate beats Secure', () => {
        expect(combine_verdicts(Verdict.Indeterminate, Verdict.Secure)).toBe(Verdict.Indeterminate);
        expect(combine_verdicts(Verdict.Secure, Verdict.Indeterminate)).toBe(Verdict.Indeterminate);
    });

    it('preserves the more specific Secure flavour', () => {
        expect(combine_verdicts(Verdict.Secure, Verdict.SecureNoData)).toBe(Verdict.SecureNoData);
        expect(combine_verdicts(Verdict.SecureNXDomain, Verdict.Secure)).toBe(Verdict.SecureNXDomain);
    });
});

describe('synthesise_dname_target', () => {
    it('rewrites strict-suffix labels under owner with target', () => {
        expect(synthesise_dname_target('foo.bar.example.com.', 'example.com.', 'elsewhere.net.'))
            .toBe('foo.bar.elsewhere.net.');
    });

    it('returns "" for qname equal to owner (RFC 6672 §3.1)', () => {
        expect(synthesise_dname_target('example.com.', 'example.com.', 'elsewhere.net.')).toBe('');
    });

    it('returns "" when qname does not end with owner', () => {
        expect(synthesise_dname_target('foo.bar.example.org.', 'example.com.', 'elsewhere.net.')).toBe('');
    });

    it('is case-insensitive on the owner suffix', () => {
        expect(synthesise_dname_target('Foo.Example.COM.', 'EXAMPLE.com.', 'elsewhere.net.'))
            .toBe('foo.elsewhere.net.');
    });
});

describe('Verifier alias chasing (UP-005 / #9)', () => {
    it('follows a single CNAME hop and records it in result.aliases', async () => {
        // Two-level chain: root → example. is signed. www.example.
        // CNAMEs to host.example.; host.example. has the A record.
        const root = make_zone('.');
        const example = make_zone('example.');
        delegate(root, example);

        add_signed(example, 'www.example.', 'CNAME', 'host.example.');
        add_signed(example, 'host.example.', 'A', '192.0.2.1');

        const resolver = new MapResolver([
            [key('.', TYPE_DNSKEY), find_with_sigs(root.zone, '.', TYPE_DNSKEY)],
            [key('example.', TYPE_DS), find_with_sigs(root.zone, 'example.', TYPE_DS)],
            [key('example.', TYPE_DNSKEY), find_with_sigs(example.zone, 'example.', TYPE_DNSKEY)],
            // CNAME is at www.example. — answer the A query with CNAME +
            // its RRSIG.
            [key('www.example.', TYPE_A), find_with_sigs(example.zone, 'www.example.', TYPE_CNAME)],
            [key('www.example.', TYPE_DS), []],
            [key('host.example.', TYPE_DS), []],
            [key('host.example.', TYPE_A), find_with_sigs(example.zone, 'host.example.', TYPE_A)],
        ]);
        const v = new Verifier({ resolver, trustAnchors: trust_anchor_for(root) });

        const result = await v.validate('www.example.', TYPE_A);
        expect(result.verdict).toBe(Verdict.Secure);
        expect(result.aliases).toBeDefined();
        expect(result.aliases!.length).toBe(1);
        expect(result.aliases![0]).toEqual({
            type:    'cname',
            from:    'www.example.',
            target:  'host.example.',
            zone:    'example.',
            verdict: Verdict.Secure,
        });
    });

    it('chases a two-step CNAME chain and worst-of combines per hop', async () => {
        // a → b → c, c is Secure. Final verdict Secure; aliases has 2.
        const root = make_zone('.');
        const example = make_zone('example.');
        delegate(root, example);

        add_signed(example, 'a.example.', 'CNAME', 'b.example.');
        add_signed(example, 'b.example.', 'CNAME', 'c.example.');
        add_signed(example, 'c.example.', 'A', '192.0.2.3');

        const resolver = new MapResolver([
            [key('.', TYPE_DNSKEY), find_with_sigs(root.zone, '.', TYPE_DNSKEY)],
            [key('example.', TYPE_DS), find_with_sigs(root.zone, 'example.', TYPE_DS)],
            [key('example.', TYPE_DNSKEY), find_with_sigs(example.zone, 'example.', TYPE_DNSKEY)],
            [key('a.example.', TYPE_A), find_with_sigs(example.zone, 'a.example.', TYPE_CNAME)],
            [key('a.example.', TYPE_DS), []],
            [key('b.example.', TYPE_A), find_with_sigs(example.zone, 'b.example.', TYPE_CNAME)],
            [key('b.example.', TYPE_DS), []],
            [key('c.example.', TYPE_A), find_with_sigs(example.zone, 'c.example.', TYPE_A)],
            [key('c.example.', TYPE_DS), []],
        ]);
        const v = new Verifier({ resolver, trustAnchors: trust_anchor_for(root) });

        const result = await v.validate('a.example.', TYPE_A);
        expect(result.verdict).toBe(Verdict.Secure);
        expect(result.aliases!.map(a => `${a.from}→${a.target}`)).toEqual([
            'a.example.→b.example.',
            'b.example.→c.example.',
        ]);
    });

    it('synthesises DNAME targets and follows them', async () => {
        // DNAME at "old.example." → "new.example.": a query for
        // "x.old.example." should be rewritten to "x.new.example.".
        const root = make_zone('.');
        const example = make_zone('example.');
        delegate(root, example);

        add_signed(example, 'old.example.', 'DNAME', 'new.example.');
        add_signed(example, 'x.new.example.', 'A', '192.0.2.7');

        const resolver = new MapResolver([
            [key('.', TYPE_DNSKEY), find_with_sigs(root.zone, '.', TYPE_DNSKEY)],
            [key('example.', TYPE_DS), find_with_sigs(root.zone, 'example.', TYPE_DS)],
            [key('example.', TYPE_DNSKEY), find_with_sigs(example.zone, 'example.', TYPE_DNSKEY)],
            // The A query at the original qname returns the DNAME at
            // its ancestor "old.example.".
            [key('x.old.example.', TYPE_A), find_with_sigs(example.zone, 'old.example.', TYPE_DNAME)],
            [key('x.old.example.', TYPE_DS), []],
            [key('old.example.', TYPE_DS), []],
            [key('x.new.example.', TYPE_DS), []],
            [key('new.example.', TYPE_DS), []],
            [key('x.new.example.', TYPE_A), find_with_sigs(example.zone, 'x.new.example.', TYPE_A)],
        ]);
        const v = new Verifier({ resolver, trustAnchors: trust_anchor_for(root) });

        const result = await v.validate('x.old.example.', TYPE_A);
        expect(result.verdict).toBe(Verdict.Secure);
        expect(result.aliases!.length).toBe(1);
        expect(result.aliases![0].type).toBe('dname');
        expect(result.aliases![0].from).toBe('x.old.example.');
        expect(result.aliases![0].target).toBe('x.new.example.');
    });

    it('detects a CNAME ping-pong loop as Bogus', async () => {
        // a → b → a → … — loop after one round-trip. validate should
        // detect the repeat and return Bogus rather than spin to the
        // hop cap.
        const root = make_zone('.');
        const example = make_zone('example.');
        delegate(root, example);

        add_signed(example, 'a.example.', 'CNAME', 'b.example.');
        add_signed(example, 'b.example.', 'CNAME', 'a.example.');

        const resolver = new MapResolver([
            [key('.', TYPE_DNSKEY), find_with_sigs(root.zone, '.', TYPE_DNSKEY)],
            [key('example.', TYPE_DS), find_with_sigs(root.zone, 'example.', TYPE_DS)],
            [key('example.', TYPE_DNSKEY), find_with_sigs(example.zone, 'example.', TYPE_DNSKEY)],
            [key('a.example.', TYPE_A), find_with_sigs(example.zone, 'a.example.', TYPE_CNAME)],
            [key('a.example.', TYPE_DS), []],
            [key('b.example.', TYPE_A), find_with_sigs(example.zone, 'b.example.', TYPE_CNAME)],
            [key('b.example.', TYPE_DS), []],
        ]);
        const v = new Verifier({ resolver, trustAnchors: trust_anchor_for(root) });

        const result = await v.validate('a.example.', TYPE_A);
        expect(result.verdict).toBe(Verdict.Bogus);
        expect(result.bogusReason).toMatch(/alias loop/);
        // We followed at least one hop before detecting the loop.
        expect(result.aliases!.length).toBeGreaterThanOrEqual(1);
    });

    it('Bogus from a tampered CNAME signature dominates the final verdict', async () => {
        // www → host (CNAME signed) → host's A is fine. Tamper the
        // CNAME RRSIG so the alias hop itself goes Bogus. Worst-of
        // says the chain is Bogus even if the target would have been
        // Secure on its own.
        const root = make_zone('.');
        const example = make_zone('example.');
        delegate(root, example);
        add_signed(example, 'www.example.', 'CNAME', 'host.example.');
        add_signed(example, 'host.example.', 'A', '192.0.2.1');

        // Wreck the CNAME's RRSIG by overwriting its signature with
        // zeros (matches the leaf-RRSIG-bogus test pattern).
        const legitSig = example.zone.find_rrset('www.example.', TYPE_RRSIG)[0];
        const sigHandler = legitSig.get_handler() as RRSig;
        const garbage = Buffer.alloc(sigHandler.signature.length).toString('base64');
        const tamperedValue = `CNAME ${sigHandler.algorithm} ${sigHandler.labels} 3600 ${sigHandler.expire} ${sigHandler.inception} ${sigHandler.key_tag} ${sigHandler.signer} ${garbage}`;
        const tamperedZone = example.zone as unknown as { records: Map<string, ResourceRecord[]> };
        tamperedZone.records.set(`www.example.\0${TYPE_RRSIG}`, [new ResourceRecord('www.example.', 3600, 'IN', 'RRSIG', tamperedValue)]);

        const resolver = new MapResolver([
            [key('.', TYPE_DNSKEY), find_with_sigs(root.zone, '.', TYPE_DNSKEY)],
            [key('example.', TYPE_DS), find_with_sigs(root.zone, 'example.', TYPE_DS)],
            [key('example.', TYPE_DNSKEY), find_with_sigs(example.zone, 'example.', TYPE_DNSKEY)],
            [key('www.example.', TYPE_A), find_with_sigs(example.zone, 'www.example.', TYPE_CNAME)],
            [key('www.example.', TYPE_DS), []],
            [key('host.example.', TYPE_A), find_with_sigs(example.zone, 'host.example.', TYPE_A)],
            [key('host.example.', TYPE_DS), []],
        ]);
        const v = new Verifier({ resolver, trustAnchors: trust_anchor_for(root) });

        const result = await v.validate('www.example.', TYPE_A);
        expect(result.verdict).toBe(Verdict.Bogus);
        expect(result.bogusReason).toMatch(/CNAME/);
    });

    it('returns Bogus when the alias chain exceeds MAX_ALIAS_HOPS', async () => {
        // Build a strictly forward chain longer than MAX_ALIAS_HOPS by
        // emitting CNAMEs n0 → n1 → … → n<MAX_ALIAS_HOPS+2>. Each step
        // is a fresh qname so the loop-detection set never triggers;
        // the hop cap is what should fire.
        const root = make_zone('.');
        const example = make_zone('example.');
        delegate(root, example);

        const chain_len = MAX_ALIAS_HOPS + 2;
        for (let i = 0; i < chain_len; i++) {
            add_signed(example, `n${i}.example.`, 'CNAME', `n${i + 1}.example.`);
        }

        const entries: [string, ResourceRecord[]][] = [
            [key('.', TYPE_DNSKEY), find_with_sigs(root.zone, '.', TYPE_DNSKEY)],
            [key('example.', TYPE_DS), find_with_sigs(root.zone, 'example.', TYPE_DS)],
            [key('example.', TYPE_DNSKEY), find_with_sigs(example.zone, 'example.', TYPE_DNSKEY)],
        ];
        for (let i = 0; i < chain_len; i++) {
            entries.push([key(`n${i}.example.`, TYPE_A), find_with_sigs(example.zone, `n${i}.example.`, TYPE_CNAME)]);
            entries.push([key(`n${i}.example.`, TYPE_DS), []]);
        }
        const resolver = new MapResolver(entries);
        const v = new Verifier({ resolver, trustAnchors: trust_anchor_for(root) });

        const result = await v.validate('n0.example.', TYPE_A);
        expect(result.verdict).toBe(Verdict.Bogus);
        expect(result.bogusReason).toMatch(new RegExp(`${MAX_ALIAS_HOPS}`));
    });
});
