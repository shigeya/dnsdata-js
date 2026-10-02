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
        'parse_message',
        'rdata_to_string',
        'Header',
    ])('exports %s', (name) => {
        expect((core as Record<string, unknown>)[name]).toBeDefined();
    });

    it('parses a message and presents its RDATA from entry-point names alone', () => {
        const query = core.build_query_with_id(0x1234, 'example.com.', 1);
        const msg: core.RawMessage = core.parse_message(query);
        expect(msg.header.id).toBe(0x1234);
        expect(msg.question.name).toBe('example.com.');
        const a = Uint8Array.of(192, 0, 2, 1);
        expect(core.rdata_to_string(a, 1, a, 0)).toBe('192.0.2.1');
    });

    it('builds a Verifier from entry-point types alone', () => {
        const resolver: core.Resolver = {
            query: async (): Promise<core.ResolverResponse> => ({ records: [], ad: false, rcode: 0 }),
        };
        const v = new core.Verifier({ resolver, cache: new core.MemoryCache() });
        expect(v).toBeInstanceOf(core.Verifier);
    });
});
