// Ports dnsdata-go `resolver/memory/example_test.go` (Example) as a
// documented test: validate a name under a private root. Sign "." →
// "test." → "example.test.", serve the three zones from memory, and make
// the root's KSK the verifier's trust anchor. Nothing touches the
// network or the real root.

import {
    AlgoECDSAP256SHA256,
    memory,
    registerAllHandlers,
    RRTypeName,
    signer,
    StringToRRType,
    Verifier,
    Zone,
} from '../../../src/index';

describe('memory authority example: validation under a private root', () => {
    it('validates a positive answer, NODATA and NXDOMAIN', async () => {
        const from = new Date(Date.UTC(2026, 0, 1));
        const opts = { inception: from, expiration: new Date(Date.UTC(2027, 0, 1)) };

        const rootKey = signer.generate_key('.', AlgoECDSAP256SHA256, signer.FlagsKSK);
        const tldKey = signer.generate_key('test.', AlgoECDSAP256SHA256, signer.FlagsKSK);
        const leafKey = signer.generate_key('example.test.', AlgoECDSAP256SHA256, signer.FlagsKSK);

        registerAllHandlers(); // the strict reader needs the DS encoder
        const build = (apex: string, text: string, key: signer.Key): Zone => {
            const z = new Zone();
            z.read_string_strict(text);
            return signer.sign_zone(z, apex, [key], opts);
        };
        const root = build('.', '. 86400 NS a.root.test.\ntest. 86400 NS ns.test.\n' +
            `test. 86400 DS ${tldKey.ds(signer.DigestSHA256)}\n`, rootKey);
        const tld = build('test.', 'test. 3600 NS ns.test.\nexample.test. 3600 NS ns.example.test.\n' +
            `example.test. 3600 DS ${leafKey.ds(signer.DigestSHA256)}\n`, tldKey);
        const leaf = build('example.test.',
            'example.test. 3600 NS ns.example.test.\nwww.example.test. 3600 A 192.0.2.10\n', leafKey);

        const auth = memory.new_authority(
            memory.with_zone('.', root),
            memory.with_zone('test.', tld),
            memory.with_zone('example.test.', leaf),
        );
        const v = new Verifier({
            resolver: auth,
            trustAnchors: signer.root_anchors(rootKey),
            now: () => new Date(Date.UTC(2026, 6, 1)),
        });

        const lines: string[] = [];
        for (const [name, qtype] of [['www.example.test.', 'A'], ['www.example.test.', 'MX'], ['nope.example.test.', 'A']]) {
            const res = await v.validate(name, StringToRRType(qtype));
            lines.push(`${name} ${RRTypeName(StringToRRType(qtype))} ${res.verdict}`);
        }
        expect(lines).toEqual([
            'www.example.test. A secure',
            'www.example.test. MX secure-nodata',
            'nope.example.test. A secure-nxdomain',
        ]);
    });
});
