// ZoneStep contents: dsDigests and the per-RRSIG signatures. Ports
// dnsdata-go `verifier/zonestep_test.go` and `verifier/sigcheck_test.go`.

import { SigStatus } from '../../src/dnssec/sigcheck';
import { RRTypeName } from '../../src/types/dns_type_table';
import { Result, SigCheck, Verdict, VerifierOptions, ZoneStep } from '../../src/verifier';
import {
    ALGO_RSASHA256, EXPIRE, INCEPTION, LEAF_NAME, LEAF_ZONE, TYPE_A, TYPE_DS, ThreeLevelChain,
    add_signed_rr, new_verifier, rrsigs_only, sign_with, tampered, three_level_chain, trust_anchor_for,
    without_rrsigs,
} from './key_auth_fixtures';

const DIGEST_SHA256 = 2;
const SECONDS_PER_DAY = 86400;
const TYPE_CNAME = 5;

function validate(c: ThreeLevelChain, qname = LEAF_NAME, opts: Partial<VerifierOptions> = {}): Promise<Result> {
    return new_verifier(c.resolver, c.root.ksk, opts).validate(qname, TYPE_A);
}

function rfc3339(seconds: number): string {
    return new Date(seconds * 1000).toISOString().replace('.000Z', 'Z');
}

function step_of(res: Result, zone: string): ZoneStep {
    const step = res.chain.find((s) => s.zone === zone);
    if (!step) throw new Error(`no step for ${zone} in ${JSON.stringify(res.chain)}`);
    return step;
}

// sig_summary renders a step's checks as "name/TYPE=result" in order.
function sig_summary(step: ZoneStep): string {
    return (step.signatures ?? []).map((s) => `${s.name}/${RRTypeName(s.rrType)}=${s.result}`).join(' ');
}

function tamper_rrsigs(c: ThreeLevelChain, name: string, qtype: number): void {
    const answer = c.resolver.answer(name, qtype);
    c.resolver.set(name, qtype, [...without_rrsigs(answer), ...rrsigs_only(answer).map(tampered)]);
}

describe('ZoneStep.dsDigests', () => {
    it('lists, below the root, the DS records that authorised the descent', async () => {
        const c = three_level_chain();
        const res = await validate(c);
        expect(res.verdict).toBe(Verdict.Secure);

        const want: Record<string, number> = { 'com.': c.com.ksk.key_tag, 'example.com.': c.leaf.ksk.key_tag };
        expect(res.chain.map((s) => s.zone)).toEqual(['.', 'com.', 'example.com.']);
        for (const step of res.chain) {
            const tag = want[step.zone];
            if (tag === undefined) {
                expect(step.dsDigests ?? []).toEqual([]);
                continue;
            }
            expect([step.zone, step.dsDigests]).toEqual(
                [step.zone, [{ keyTag: tag, algorithm: ALGO_RSASHA256, digestType: DIGEST_SHA256 }]]);
        }
    });
});

describe('ZoneStep.signatures', () => {
    it('lists the DS, DNSKEY and answer checks of a secure chain', async () => {
        const c = three_level_chain();
        const res = await validate(c);
        expect(res.verdict).toBe(Verdict.Secure);
        expect(res.chain.map((s) => [s.zone, sig_summary(s)])).toEqual([
            ['.', './DNSKEY=verified'],
            ['com.', 'com./DS=verified com./DNSKEY=verified'],
            ['example.com.', 'example.com./DS=verified example.com./DNSKEY=verified www.example.com./A=verified'],
        ]);

        const a = step_of(res, LEAF_ZONE).signatures?.[2];
        const want: SigCheck = {
            name: LEAF_NAME, rrType: TYPE_A, keyTag: c.leaf.ksk.key_tag, algorithm: ALGO_RSASHA256,
            signer: LEAF_ZONE, inception: rfc3339(INCEPTION), expiration: rfc3339(EXPIRE), result: SigStatus.Verified,
        };
        expect(a).toEqual(want);
        const ds = step_of(res, 'com.').signatures?.[0];
        expect([ds?.signer, ds?.keyTag]).toEqual(['.', c.root.ksk.key_tag]);
    });

    it('lists every RRSIG, not only the first that verifies', async () => {
        const c = three_level_chain();
        sign_with(c.leaf.zone, LEAF_NAME, TYPE_A, c.leaf.ksk, false,
            INCEPTION - 3 * SECONDS_PER_DAY, INCEPTION - 2 * SECONDS_PER_DAY);
        const res = await validate(c);
        expect(res.verdict).toBe(Verdict.Secure);
        const got = sig_summary(step_of(res, LEAF_ZONE));
        expect(got).toContain('www.example.com./A=verified');
        expect(got).toContain('www.example.com./A=expired');
    });

    it('adds to a step an earlier alias hop made only the checks it lacks', async () => {
        const c = three_level_chain();
        add_signed_rr(c.leaf.zone, 'alias.example.com.', 'CNAME', LEAF_NAME, c.leaf.ksk);
        c.resolver.set('alias.example.com.', TYPE_A, c.resolver.answer('alias.example.com.', TYPE_CNAME));
        const res = await validate(c, 'alias.example.com.');
        expect(res.verdict).toBe(Verdict.Secure);
        expect(res.chain.map((s) => [s.zone, sig_summary(s)])).toEqual([
            ['.', './DNSKEY=verified'],
            ['com.', 'com./DS=verified com./DNSKEY=verified'],
            ['example.com.', 'example.com./DS=verified example.com./DNSKEY=verified ' +
                'alias.example.com./CNAME=verified www.example.com./A=verified'],
        ]);
    });

    it.each([
        ['invalid DS signature', (c: ThreeLevelChain) => { tamper_rrsigs(c, 'com.', TYPE_DS); return {}; },
            'com.', 'com./DS=invalid', false],
        ['expired root', () => ({ now: () => new Date((EXPIRE + 2 * SECONDS_PER_DAY) * 1000) }),
            '.', './DNSKEY=expired', false],
        ['invalid answer signature', (c: ThreeLevelChain) => { tamper_rrsigs(c, LEAF_NAME, TYPE_A); return {}; },
            LEAF_ZONE, 'example.com./DS=verified example.com./DNSKEY=verified www.example.com./A=invalid', true],
    ] as const)('ends a Bogus chain with the failing zone (%s)', async (_name, setup, zone, summary, signed) => {
        const c = three_level_chain();
        const res = await validate(c, LEAF_NAME, setup(c));
        expect(res.verdict).toBe(Verdict.Bogus);
        const last = res.chain[res.chain.length - 1];
        expect([last.zone, sig_summary(last)]).toEqual([zone, summary]);
        expect(last.signedBy !== undefined).toBe(signed);
    });

    it('lists the root step, without checks, on a trust anchor mismatch', async () => {
        const c = three_level_chain();
        const res = await validate(c, LEAF_NAME, { trustAnchors: trust_anchor_for(c.com.ksk) });
        expect(res.verdict).toBe(Verdict.Bogus);
        expect(res.chain).toHaveLength(1);
        expect(res.chain[0].zone).toBe('.');
        expect(res.chain[0].dnskeys).toHaveLength(1);
        expect(res.chain[0].signatures).toBeUndefined();
        expect(res.chain[0].signedBy).toBeUndefined();
    });

    it('serialises as plain JSON with the Go field names', async () => {
        const c = three_level_chain();
        const res = await validate(c);
        const json = JSON.stringify(res.chain[0]);
        for (const key of ['"signatures":[', '"name":"."', '"rrType":48', '"keyTag":', `"algorithm":${ALGO_RSASHA256}`,
            '"signer":"."', `"inception":"${rfc3339(INCEPTION)}"`, `"expiration":"${rfc3339(EXPIRE)}"`,
            '"result":"verified"']) {
            expect(json).toContain(key);
        }
        expect(JSON.parse(JSON.stringify(res))).toEqual(res);
    });
});
