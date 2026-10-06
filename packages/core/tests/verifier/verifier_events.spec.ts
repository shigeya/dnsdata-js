// VerifierOptions.onStep: the steps of every validate() call. Ports
// dnsdata-go `verifier/events_test.go`.

import {
    MemoryCache, Result, SigCheck, StepEvent, StepKind, Verdict, VerifierChainTimeoutError, VerifierOptions,
} from '../../src/verifier';
import {
    LEAF_NAME, TYPE_A, TYPE_DS, ThreeLevelChain, add_signed_rr, new_verifier, rrset_with_sigs, rrsigs_only, tampered,
    three_level_chain, without_rrsigs,
} from './key_auth_fixtures';

const TYPE_CNAME = 5;
const TYPE_NSEC = 47;

// collect validates qname over c with a step handler and returns the
// result and the events seen. The handler fails the test if it runs
// after validate() settled.
async function collect(c: ThreeLevelChain, qname: string, opts: Partial<VerifierOptions> = {}):
        Promise<{ res: Result; events: StepEvent[] }> {
    const events: StepEvent[] = [];
    let settled = false;
    const onStep = (e: StepEvent): void => {
        if (settled) throw new Error('step handler called after validate() settled');
        events.push(e);
    };
    try {
        const res = await new_verifier(c.resolver, c.root.ksk, { ...opts, onStep }).validate(qname, TYPE_A);
        return { res, events };
    } finally {
        settled = true;
    }
}

function events_of(events: StepEvent[], kind: StepKind): StepEvent[] {
    return events.filter((e) => e.kind === kind);
}

function chain_sigs(res: Result): Array<{ zone: string; sig: SigCheck }> {
    return res.chain.flatMap((step) => (step.signatures ?? []).map((sig) => ({ zone: step.zone, sig })));
}

describe('VerifierOptions.onStep', () => {
    it('has the Go kind names', () => {
        expect([
            StepKind.Query, StepKind.CacheHit, StepKind.DS, StepKind.DNSKEY, StepKind.Zone, StepKind.Sig,
            StepKind.Alias, StepKind.Insecure, StepKind.Bogus, StepKind.Answer,
        ]).toEqual(['query', 'cache-hit', 'ds', 'dnskey', 'zone', 'sig', 'alias', 'insecure', 'bogus', 'answer']);
    });

    it('streams a secure chain: zones root first, one sig event per SigCheck, answer last', async () => {
        const c = three_level_chain();
        const { res, events } = await collect(c, LEAF_NAME);

        expect(events_of(events, StepKind.Zone).map((e) => e.zone)).toEqual(['.', 'com.', 'example.com.']);
        const sigs = events_of(events, StepKind.Sig);
        expect(sigs.map((e) => ({ zone: e.zone, sig: e.sig }))).toEqual(chain_sigs(res));
        for (const kind of [StepKind.Query, StepKind.DS, StepKind.DNSKEY]) {
            expect([kind, events_of(events, kind).length > 0]).toEqual([kind, true]);
        }
        expect(events_of(events, StepKind.Query)[0]).toEqual({ kind: StepKind.Query, zone: '.', detail: 'DNSKEY' });
        expect(events_of(events, StepKind.DS)[0]).toEqual({ kind: StepKind.DS, zone: 'com.', detail: 'verified' });
        expect(events[events.length - 1]).toEqual({ kind: StepKind.Answer, zone: LEAF_NAME, detail: 'secure' });
    });

    it('hands the handler a copy of each SigCheck', async () => {
        const c = three_level_chain();
        const { res, events } = await collect(c, LEAF_NAME);
        for (const e of events_of(events, StepKind.Sig)) {
            if (e.sig) e.sig.result = 'tampered' as SigCheck['result'];
        }
        expect(chain_sigs(res).every(({ sig }) => sig.result === 'verified')).toBe(true);
    });

    it('reports an alias hop and a Bogus verdict', async () => {
        const c = three_level_chain();
        add_signed_rr(c.leaf.zone, 'alias.example.com.', 'CNAME', LEAF_NAME, c.leaf.ksk);
        c.resolver.set('alias.example.com.', TYPE_A, c.resolver.answer('alias.example.com.', TYPE_CNAME));
        const answer = c.resolver.answer(LEAF_NAME, TYPE_A);
        c.resolver.set(LEAF_NAME, TYPE_A, [...without_rrsigs(answer), ...rrsigs_only(answer).map(tampered)]);

        const { res, events } = await collect(c, 'alias.example.com.');
        expect(res.verdict).toBe(Verdict.Bogus);
        expect(events_of(events, StepKind.Alias)).toEqual([
            { kind: StepKind.Alias, zone: 'example.com.', detail: `cname alias.example.com. -> ${LEAF_NAME}` },
        ]);
        expect(events_of(events, StepKind.Bogus)).toEqual([
            { kind: StepKind.Bogus, zone: res.bogusAt, detail: `${res.reasonCode}: ${res.bogusReason}` },
        ]);
        expect(events_of(events, StepKind.Sig)).toHaveLength(chain_sigs(res).length);
        expect(events[events.length - 1]).toEqual({ kind: StepKind.Answer, zone: LEAF_NAME, detail: 'bogus' });
    });

    it('reports cache hits instead of queries', async () => {
        const c = three_level_chain();
        const cache = new MemoryCache();
        await collect(c, LEAF_NAME, { cache });
        const { events } = await collect(c, LEAF_NAME, { cache });
        expect(events_of(events, StepKind.CacheHit).length).toBeGreaterThan(0);
        expect(events_of(events, StepKind.Query)).toHaveLength(0);
    });

    it('reports an Insecure verdict', async () => {
        const c = three_level_chain();
        add_signed_rr(c.com.zone, 'insecure.com.', 'NSEC', 'j.com. NS RRSIG NSEC', c.com.ksk);
        c.resolver.set('insecure.com.', TYPE_DS, rrset_with_sigs(c.com.zone, 'insecure.com.', TYPE_NSEC));
        const { events } = await collect(c, 'www.insecure.com.');
        expect(events_of(events, StepKind.Insecure).map((e) => e.zone)).toEqual(['insecure.com.']);
    });

    it('costs nothing without a handler', async () => {
        const c = three_level_chain();
        const res = await new_verifier(c.resolver, c.root.ksk, { onStep: undefined }).validate(LEAF_NAME, TYPE_A);
        expect(res.verdict).toBe(Verdict.Secure);
    });

    it('is not called after a failing validate() settles', async () => {
        const c = three_level_chain();
        let settled = false;
        let late = 0;
        const v = new_verifier(c.resolver, c.root.ksk, { onStep: () => { if (settled) late++; } });
        const controller = new AbortController();
        controller.abort();
        await expect(v.validate(LEAF_NAME, TYPE_A, controller.signal)).rejects.toThrow(VerifierChainTimeoutError);
        settled = true;
        await new Promise((resolve) => setImmediate(resolve));
        expect(late).toBe(0);
    });
});
