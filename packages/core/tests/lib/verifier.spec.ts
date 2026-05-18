// Verifier tests
//
// Builds in-memory signed zones, threads them through a mock
// Resolver, and asserts the chain walker reaches the expected
// verdict. The interesting fixture is the `.jp.` shape (#5 / UP-001
// from dnsdata-go) where `ad.jp.` is an empty non-terminal between
// two real zone cuts — a naive descent loop that exits on the first
// no-DS response will leaf-resolve under the wrong zone's keys.

import * as crypto from 'crypto';

import { DNSSecZone } from '../../src/lib/dnssec_zone';
import { DNSKey, RRSig } from '../../src/lib/dnssec_rr';
import { ResourceRecord } from '../../src/lib/dns_zone';
import { StringToRRType } from '../../src/lib/dns_type_table';
import { RootAnchors } from '../../src/lib/root_anchors';
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
} from '../../src/lib/verifier';

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
        const resolver: Resolver = { async query() { return []; } };
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
        const resolver: Resolver = { async query() { return []; } };
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

    it('returns Indeterminate when the leaf rrset is missing (NODATA — NSEC proofs out of v0.1.0 scope)', async () => {
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
