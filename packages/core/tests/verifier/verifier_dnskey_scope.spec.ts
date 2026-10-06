// A DNSKEY is taken only from the answer to the DNSKEY query for its own
// owner name. One carried in any other answer (the leaf answer, or a DS
// answer asked of the zone) arrives after the zone's DNSKEY rrset was
// authenticated and must not become a signing key of the zone: leaf, DS
// and negative data are checked in KeyVerifyMode.None. Ports
// dnsdata-go `verifier/dnskeyscope_test.go`.

import { Verdict } from '../../src/verifier';
import {
    ATTACKER_ADDR, CHILD, TYPE_A, TYPE_DNSKEY, TYPE_DS,
    ZoneCollectionResolver, add_signed, legit_child, make_zone, new_verifier, rrset_with_sigs,
} from './key_auth_fixtures';

const EVIL = 'evil.example.';

describe('Verifier: DNSKEY outside its own DNSKEY answer', () => {
    it.each([
        ['leaf answer', EVIL, TYPE_A],
        ['DS answer', EVIL, TYPE_DS], // asked of example.
    ])('does not let a DNSKEY in the %s sign data', async (_name, qname, qtype) => {
        const root = make_zone('.');
        const child = legit_child(root);
        const attacker = make_zone(CHILD);
        add_signed(attacker.zone, EVIL, ATTACKER_ADDR, attacker.ksk);

        const resolver = new ZoneCollectionResolver([root.zone, child.zone]);
        resolver.add_extra(EVIL, TYPE_A, rrset_with_sigs(attacker.zone, EVIL, TYPE_A));
        resolver.add_extra(qname, qtype, attacker.zone.find_rrset(CHILD, TYPE_DNSKEY));

        const result = await new_verifier(resolver, root.ksk).validate(EVIL, TYPE_A);
        expect(result.verdict).toBe(Verdict.Bogus);
        expect(result.bogusAt).toBe(CHILD);
        expect(result.answer).toBeUndefined();
        const attackerKey = attacker.zone.find_rrset(CHILD, TYPE_DNSKEY)[0].value;
        expect(result.evidence.dnskeys[CHILD]).not.toContain(attackerKey);
    });
});

describe('Verifier: RRSIG by a zone whose DNSKEY rrset was never authenticated', () => {
    const SIGNER = 'unrelated.example.';
    const LEAF = 'www.example.';

    it.each([
        ['with the signer DNSKEY in the leaf answer', true],
        ['without the signer DNSKEY', false],
    ])('returns Bogus %s', async (_name, carryKey) => {
        const root = make_zone('.');
        const child = legit_child(root);
        const signer = make_zone(SIGNER);
        add_signed(signer.zone, LEAF, ATTACKER_ADDR, signer.ksk);

        const resolver = new ZoneCollectionResolver([root.zone, child.zone]);
        resolver.add_extra(LEAF, TYPE_A, rrset_with_sigs(signer.zone, LEAF, TYPE_A));
        if (carryKey) resolver.add_extra(LEAF, TYPE_A, signer.zone.find_rrset(SIGNER, TYPE_DNSKEY));

        const result = await new_verifier(resolver, root.ksk).validate(LEAF, TYPE_A);
        expect(result.verdict).toBe(Verdict.Bogus);
        expect(result.bogusAt).toBe(CHILD);
        expect(result.answer).toBeUndefined();
    });
});
