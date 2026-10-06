// ZoneStep contents. Ports dnsdata-go `verifier/zonestep_test.go`.

import { Verdict } from '../../src/verifier';
import { ALGO_RSASHA256, LEAF_NAME, TYPE_A, new_verifier, three_level_chain } from './key_auth_fixtures';

const DIGEST_SHA256 = 2;

describe('ZoneStep.dsDigests', () => {
    it('lists, below the root, the DS records that authorised the descent', async () => {
        const c = three_level_chain();
        const res = await new_verifier(c.resolver, c.root.ksk).validate(LEAF_NAME, TYPE_A);
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
