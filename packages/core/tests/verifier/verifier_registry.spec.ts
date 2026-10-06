// Each Verifier owns a handler registry and never touches the default
// one. Ports dnsdata-go `verifier/registry_test.go`.

import type * as RegistryModule from '../../src/zone/registry';
import type * as VerifierModule from '../../src/verifier/verifier';
import type * as ZoneModule from '../../src/zone/dns_zone';
import { StringToRRType } from '../../src/types/dns_type_table';
import { Verdict, MemoryCache, Verifier } from '../../src/verifier';
import { Registry, default_registry, type HandlerFactory } from '../../src/zone/registry';
import { ResourceRecordHandler } from '../../src/zone/dns_zone';
import {
    CHILD, TYPE_A, ZoneCollectionResolver, legit_child, make_zone, new_verifier, trust_anchor_for,
} from './key_auth_fixtures';

const TYPE_DNSKEY = StringToRRType('DNSKEY');

// The handler the marker factory builds.
class MarkerHandler extends ResourceRecordHandler {
    get_wire_body(): void { /* writes nothing */ }
    clone(): ResourceRecordHandler { return new MarkerHandler(null); }
}

const marker_factory: HandlerFactory = () => new MarkerHandler(null);

function chain(): { resolver: ZoneCollectionResolver; anchorKey: ReturnType<typeof make_zone>['ksk'] } {
    const root = make_zone('.');
    const child = legit_child(root);
    return { resolver: new ZoneCollectionResolver([root.zone, child.zone]), anchorKey: root.ksk };
}

describe('Verifier registry', () => {
    it('the constructor leaves the default registry untouched', () => {
        const { resolver } = chain();
        const def = default_registry();
        const prev = def.lookup(TYPE_DNSKEY) ?? null;
        def.register(TYPE_DNSKEY, marker_factory);
        try {
            new Verifier({ resolver });
            const f = def.lookup(TYPE_DNSKEY);
            expect(f).toBe(marker_factory);
        } finally {
            def.register(TYPE_DNSKEY, prev);
        }
    });

    it('validates with nothing registered globally and leaves the default registry empty', async () => {
        const { resolver, anchorKey } = chain();
        let registry: typeof RegistryModule | undefined;
        let verifier: typeof VerifierModule | undefined;
        let zone: typeof ZoneModule | undefined;
        jest.isolateModules(() => {
            registry = require('../../src/zone/registry');
            verifier = require('../../src/verifier/verifier');
            zone = require('../../src/zone/dns_zone');
        });
        if (!registry || !verifier || !zone) throw new Error('isolateModules did not run');
        const types = [TYPE_DNSKEY, StringToRRType('RRSIG'), StringToRRType('DS'), StringToRRType('NSEC')];
        expect(types.map((t) => registry!.default_registry().lookup(t))).toEqual([undefined, undefined, undefined, undefined]);

        const v = new verifier.Verifier({
            resolver, trustAnchors: trust_anchor_for(anchorKey), now: () => new Date(1500000000 * 1000),
        });
        const result = await v.validate(CHILD, TYPE_A);

        expect(`${result.verdict} ${result.bogusReason ?? ''}`).toBe(`${Verdict.Secure} `);
        expect(types.map((t) => registry!.default_registry().lookup(t))).toEqual([undefined, undefined, undefined, undefined]);
        expect(types.map((t) => zone!.has_encoder(t))).toEqual([false, false, false, false]);
    });

    it('uses VerifierOptions.registry when given', () => {
        const { resolver } = chain();
        const registry = new Registry();
        expect(new Verifier({ resolver, registry }).registry).toBe(registry);
        const own = new Verifier({ resolver }).registry;
        expect(own).not.toBe(default_registry());
        expect(own.lookup(TYPE_DNSKEY)).toBeDefined();
        expect(own.lookup(StringToRRType('TLSA'))).toBeUndefined();
    });

    it('keeps verifiers with different registries independent over one cache', async () => {
        const { resolver, anchorKey } = chain();
        const cache = new MemoryCache();
        const good = new_verifier(resolver, anchorKey, { cache });
        const blind = new_verifier(resolver, anchorKey, { cache, registry: new Registry() });

        // Prime the cache, then interleave the two.
        expect((await good.validate(CHILD, TYPE_A)).verdict).toBe(Verdict.Secure);
        const results = await Promise.all([0, 1, 2, 3, 4, 5, 6, 7].map((i) =>
            (i % 2 === 0 ? good : blind).validate(CHILD, TYPE_A)));
        expect(results.map((r) => r.verdict)).toEqual(
            [0, 1, 2, 3, 4, 5, 6, 7].map((i) => (i % 2 === 0 ? Verdict.Secure : Verdict.Bogus)));
    });
});
