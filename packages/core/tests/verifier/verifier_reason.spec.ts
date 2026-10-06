// Result.reasonCode and result_error. Ports dnsdata-go
// `verifier/reason_test.go`.

import * as crypto from 'crypto';

import { DNSKey } from '../../src/dnssec/dnssec_rr';
import { SigStatus } from '../../src/dnssec/sigcheck';
import { sig_failure_code } from '../../src/verifier/reason';
import { ResourceRecord } from '../../src/zone/dns_zone';
import {
    MAX_ALIAS_HOPS, ReasonCode, Result, Verdict, VerifierBogusError, VerifierDSMismatchError, VerifierError,
    VerifierNoDNSKEYError, VerifierNoDSError, VerifierOptions, VerifierSigExpiredError, VerifierSigInvalidError,
    VerifierTrustAnchorMismatchError, VerifierUnsupportedAlgoError, result_error,
} from '../../src/verifier';
import {
    CHILD_ADDR, EXPIRE, INCEPTION, LEAF_NAME, LEAF_ZONE, TTL, TYPE_A, TYPE_DNSKEY, TYPE_DS, ThreeLevelChain,
    add_signed, add_signed_rr, make_zone, new_verifier, rrset_with_sigs, rrsigs_only, sign_with, tampered,
    three_level_chain, trust_anchor_for, without_rrsigs,
} from './key_auth_fixtures';

const TYPE_NSEC = 47;
const SECONDS_PER_DAY = 86400;
const UNSUPPORTED_ALGORITHM = 12;

function at(seconds: number): () => Date {
    return () => new Date(seconds * 1000);
}

function chain_name(i: number): string {
    return `c${i}.example.com.`;
}

function validate(c: ThreeLevelChain, qname: string, opts: Partial<VerifierOptions> = {}): Promise<Result> {
    return new_verifier(c.resolver, c.root.ksk, opts).validate(qname, TYPE_A);
}

// tamper_rrsigs replaces the RRSIGs of the answer to (name, qtype) with
// tampered copies.
function tamper_rrsigs(c: ThreeLevelChain, name: string, qtype: number): void {
    const answer = c.resolver.answer(name, qtype);
    c.resolver.set(name, qtype, [...without_rrsigs(answer), ...rrsigs_only(answer).map(tampered)]);
}

type Setup = (c: ThreeLevelChain) => { qname: string; opts?: Partial<VerifierOptions> };
type ErrorClass = abstract new (...args: never[]) => Error;

const cases: Array<[string, Setup, Verdict, ReasonCode, ErrorClass, string]> = [
    ['expired', () => ({ qname: LEAF_NAME, opts: { now: at(EXPIRE + 2 * SECONDS_PER_DAY) } }),
        Verdict.Bogus, ReasonCode.SigExpired, VerifierSigExpiredError, '.'],
    ['not yet valid', () => ({ qname: LEAF_NAME, opts: { now: at(INCEPTION - 2 * SECONDS_PER_DAY) } }),
        Verdict.Bogus, ReasonCode.SigNotYetValid, VerifierSigExpiredError, '.'],
    ['trust anchor mismatch', () => ({ qname: LEAF_NAME, opts: { trustAnchors: trust_anchor_for(make_zone('.').ksk) } }),
        Verdict.Bogus, ReasonCode.TrustAnchorMismatch, VerifierTrustAnchorMismatchError, '.'],
    ['DS mismatch', (c) => {
        const other = make_zone(LEAF_ZONE);
        c.resolver.set(LEAF_ZONE, TYPE_DNSKEY, rrset_with_sigs(other.zone, LEAF_ZONE, TYPE_DNSKEY));
        return { qname: LEAF_NAME };
    }, Verdict.Bogus, ReasonCode.DSMismatch, VerifierDSMismatchError, LEAF_ZONE],
    ['no DNSKEY', (c) => {
        c.resolver.set(LEAF_ZONE, TYPE_DNSKEY, []);
        return { qname: LEAF_NAME };
    }, Verdict.Bogus, ReasonCode.NoDNSKEY, VerifierNoDNSKEYError, LEAF_ZONE],
    ['invalid DS signature', (c) => {
        tamper_rrsigs(c, 'com.', TYPE_DS);
        return { qname: LEAF_NAME };
    }, Verdict.Bogus, ReasonCode.SigInvalid, VerifierSigInvalidError, 'com.'],
    ['invalid answer signature', (c) => {
        tamper_rrsigs(c, LEAF_NAME, TYPE_A);
        return { qname: LEAF_NAME };
    }, Verdict.Bogus, ReasonCode.SigInvalid, VerifierSigInvalidError, LEAF_ZONE],
    ['no RRSIG', (c) => {
        c.resolver.set(LEAF_NAME, TYPE_A, without_rrsigs(c.resolver.answer(LEAF_NAME, TYPE_A)));
        return { qname: LEAF_NAME };
    }, Verdict.Bogus, ReasonCode.NoRRSIG, VerifierSigInvalidError, LEAF_ZONE],
    ['no matching key', (c) => {
        const other = make_zone(LEAF_ZONE);
        add_signed(other.zone, LEAF_NAME, CHILD_ADDR, other.ksk);
        c.resolver.set(LEAF_NAME, TYPE_A, [
            ...without_rrsigs(c.resolver.answer(LEAF_NAME, TYPE_A)),
            ...rrsigs_only(rrset_with_sigs(other.zone, LEAF_NAME, TYPE_A)),
        ]);
        return { qname: LEAF_NAME };
    }, Verdict.Bogus, ReasonCode.NoMatchingKey, VerifierSigInvalidError, LEAF_ZONE],
    ['no DS (insecure)', (c) => {
        add_signed_rr(c.com.zone, 'insecure.com.', 'NSEC', 'j.com. NS RRSIG NSEC', c.com.ksk);
        c.resolver.set('insecure.com.', TYPE_DS, rrset_with_sigs(c.com.zone, 'insecure.com.', TYPE_NSEC));
        return { qname: 'www.insecure.com.' };
    }, Verdict.Insecure, ReasonCode.NoDS, VerifierNoDSError, 'insecure.com.'],
    ['alias loop', (c) => {
        add_signed_rr(c.leaf.zone, 'a.example.com.', 'CNAME', 'b.example.com.', c.leaf.ksk);
        add_signed_rr(c.leaf.zone, 'b.example.com.', 'CNAME', 'a.example.com.', c.leaf.ksk);
        for (const n of ['a.example.com.', 'b.example.com.']) {
            c.resolver.set(n, TYPE_A, rrset_with_sigs(c.leaf.zone, n, 5));
        }
        return { qname: 'a.example.com.' };
    }, Verdict.Bogus, ReasonCode.AliasLoop, VerifierBogusError, 'a.example.com.'],
    ['alias limit', (c) => {
        for (let i = 0; i <= MAX_ALIAS_HOPS + 1; i++) {
            add_signed_rr(c.leaf.zone, chain_name(i), 'CNAME', chain_name(i + 1), c.leaf.ksk);
            c.resolver.set(chain_name(i), TYPE_A, rrset_with_sigs(c.leaf.zone, chain_name(i), 5));
        }
        return { qname: chain_name(0) };
    }, Verdict.Bogus, ReasonCode.AliasLimit, VerifierBogusError, chain_name(MAX_ALIAS_HOPS + 1)],
    ['wildcard without proof', (c) => {
        c.leaf.zone.add_rr_from_parts('foo.example.com.', TTL, 'IN', 'A', '192.0.2.99');
        const sig = c.leaf.zone.sign_rr('foo.example.com.', TTL, TYPE_A, c.leaf.ksk, INCEPTION, EXPIRE, 2);
        if (!sig) throw new Error('sign_rr failed');
        c.leaf.zone.add_rr(sig);
        return { qname: 'foo.example.com.' };
    }, Verdict.Bogus, ReasonCode.WildcardProofMissing, VerifierBogusError, LEAF_ZONE],
];

describe('Result.reasonCode', () => {
    it.each(cases)('%s', async (_name, setup, verdict, code, errorClass, failAt) => {
        const c = three_level_chain();
        const { qname, opts } = setup(c);
        const res = await validate(c, qname, opts);

        expect([res.verdict, res.reasonCode, res.bogusReason]).toEqual([verdict, code, res.bogusReason]);
        const [where, reason] = verdict === Verdict.Insecure
            ? [res.insecureAt, res.insecureReason] : [res.bogusAt, res.bogusReason];
        expect(where).toBe(failAt);

        const err = result_error(res);
        expect(err).toBeInstanceOf(errorClass);
        expect(err).toBeInstanceOf(VerifierError);
        if (verdict === Verdict.Bogus) expect(err).toBeInstanceOf(VerifierBogusError);
        else expect(err).not.toBeInstanceOf(VerifierBogusError);
        expect(err?.message).toContain(reason ?? '');
        expect(err?.message).toContain(`${code} at ${failAt}`);
        // Result stays plain JSON.
        expect(JSON.parse(JSON.stringify(res)).reasonCode).toBe(code);
    });

    it('carries unsupported-algorithm on the Indeterminate result of a rejected validate()', async () => {
        const c = three_level_chain();
        const keyData = crypto.randomBytes(64);
        const fake = new DNSKey(null, 256, 3, UNSUPPORTED_ALGORITHM, new Uint8Array(keyData));
        c.leaf.zone.add_rr_from_parts(LEAF_ZONE, TTL, 'IN', 'DNSKEY',
            `256 3 ${UNSUPPORTED_ALGORITHM} ${keyData.toString('base64')}`);
        sign_with(c.leaf.zone, LEAF_ZONE, TYPE_DNSKEY, c.leaf.ksk);
        const rrsig = new ResourceRecord(LEAF_NAME, 300, 'IN', 'RRSIG',
            `A ${UNSUPPORTED_ALGORITHM} 3 300 ${EXPIRE} ${INCEPTION} ${fake.key_tag} ${LEAF_ZONE} ` +
            crypto.randomBytes(64).toString('base64'));
        c.resolver.set(LEAF_NAME, TYPE_A, [...without_rrsigs(c.resolver.answer(LEAF_NAME, TYPE_A)), rrsig]);

        const err: unknown = await validate(c, LEAF_NAME).then(() => undefined, (e: unknown) => e);
        expect(err).toBeInstanceOf(VerifierUnsupportedAlgoError);
        expect(err).toBeInstanceOf(VerifierError);
        const res = (err as VerifierUnsupportedAlgoError).result;
        expect(res?.verdict).toBe(Verdict.Indeterminate);
        expect(res?.reasonCode).toBe(ReasonCode.UnsupportedAlgorithm);
        expect(result_error(res!)).toBeInstanceOf(VerifierUnsupportedAlgoError);
        expect(result_error(res!)).not.toBeInstanceOf(VerifierBogusError);
    });

    it('names an rrset failure by the first status present in precedence order', () => {
        const sig = three_level_chain().leaf.zone.find_rrsigs(LEAF_NAME, TYPE_A)[0];
        const of = (...statuses: SigStatus[]) => sig_failure_code(statuses.map((status) => ({ rrsig: sig, status })));
        expect(of()).toBe(ReasonCode.NoRRSIG);
        expect(of(SigStatus.Invalid, SigStatus.Expired)).toBe(ReasonCode.SigExpired);
        expect(of(SigStatus.Invalid, SigStatus.NotYetValid)).toBe(ReasonCode.SigNotYetValid);
        expect(of(SigStatus.NoMatchingKey, SigStatus.Invalid)).toBe(ReasonCode.SigInvalid);
        expect(of(SigStatus.UnsupportedAlgorithm, SigStatus.NoMatchingKey)).toBe(ReasonCode.NoMatchingKey);
        expect(of(SigStatus.UnsupportedAlgorithm, SigStatus.UnsupportedAlgorithm)).toBe(ReasonCode.UnsupportedAlgorithm);
    });

    it('keeps a non-Bogus code on a Bogus verdict as the cause', () => {
        const res: Result = {
            verdict: Verdict.Bogus, chain: [], evidence: { dnskeys: {}, dses: {}, rrsigs: {} },
            bogusAt: 'example.', bogusReason: 'r', reasonCode: ReasonCode.NoDS,
        };
        const err = result_error(res);
        expect(err).toBeInstanceOf(VerifierBogusError);
        expect((err as VerifierBogusError).cause).toBeInstanceOf(VerifierNoDSError);
        expect(err?.message).toBe('verifier: no-ds at example.: r');
    });

    it('has no code and no error without a failure', async () => {
        const c = three_level_chain();
        const res = await validate(c, LEAF_NAME);
        expect(res.verdict).toBe(Verdict.Secure);
        expect(res.reasonCode).toBeUndefined();
        expect(result_error(res)).toBeUndefined();
    });
});
