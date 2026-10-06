// DNSSecZone and the DNSSEC handler set with a caller-owned Registry.
// Ports dnsdata-go `dnssec/registry_test.go`.

import { KeyVerifyMode, DNSSecZone } from '../../src/dnssec/dnssec_zone';
import { register_dnssec_handlers_into } from '../../src/dnssec/handlers';
import { StringToRRType } from '../../src/types/dns_type_table';
import { Registry, default_registry } from '../../src/zone/registry';
import { CHILD_ADDR, TYPE_A, add_signed, make_zone } from '../verifier/key_auth_fixtures';

const LEAF = 'www.reg.example.';

describe('register_dnssec_handlers_into', () => {
    it('installs the DNSSEC set only', () => {
        const registry = new Registry();
        register_dnssec_handlers_into(registry);
        for (const t of ['DNSKEY', 'CDNSKEY', 'RRSIG', 'DS', 'CDS', 'NSEC', 'NSEC3', 'NSEC3PARAM']) {
            expect([t, registry.lookup(StringToRRType(t)) !== undefined]).toEqual([t, true]);
        }
        expect(registry.lookup(StringToRRType('TLSA'))).toBeUndefined();
    });
});

describe('DNSSecZone registry', () => {
    it('resolves handlers through the registry it was given', () => {
        const setup = make_zone('reg.example.');
        add_signed(setup.zone, LEAF, CHILD_ADDR, setup.ksk);
        const z = setup.zone;

        z.set_registry(new Registry());
        expect(z.find_rrsigs(LEAF, TYPE_A)).toHaveLength(0);
        expect(z.verify_rrset(LEAF, TYPE_A, KeyVerifyMode.None)).toBe(false);

        const registry = new Registry();
        register_dnssec_handlers_into(registry);
        z.set_registry(registry);
        expect(z.get_registry()).toBe(registry);
        expect(z.verify_rrset(LEAF, TYPE_A, KeyVerifyMode.None)).toBe(true);
    });

    it('defaults to the default registry', () => {
        const z = new DNSSecZone();
        expect(z.get_registry()).toBe(default_registry());
        z.set_registry(new Registry());
        z.set_registry(null);
        expect(z.get_registry()).toBe(default_registry());
    });
});
