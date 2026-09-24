// The package entry point exposes the public contract of DESIGN.md
// §3 / §4, so callers never import from per-file modules.

import * as core from '../src/index';

describe('@dnsdata/core entry point', () => {
    it.each([
        'Verifier',
        'Verdict',
        'MemoryCache',
        'VerifierError',
        'VerifierConfigError',
        'VerifierInvalidQNameError',
        'VerifierResolverError',
        'VerifierChainTimeoutError',
        'VerifierTrustAnchorMismatchError',
        'DoHClient',
        'AuthClient',
        'registerAllHandlers',
        'signer',
        'memory',
    ])('exports %s', (name) => {
        expect((core as Record<string, unknown>)[name]).toBeDefined();
    });

    it('builds a Verifier from entry-point types alone', () => {
        const resolver: core.Resolver = {
            query: async (): Promise<core.ResolverResponse> => ({ records: [], ad: false, rcode: 0 }),
        };
        const v = new core.Verifier({ resolver, cache: new core.MemoryCache() });
        expect(v).toBeInstanceOf(core.Verifier);
    });
});
