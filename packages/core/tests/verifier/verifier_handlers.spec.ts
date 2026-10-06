// Ports dnsdata-go `verifier/handlers_test.go`.
//
// tests/testdata/handlers holds a signed root zone, shared byte for byte
// with dnsdata-go, whose TLSA, SMIMEA, SVCB and HTTPS records are written
// in RFC 3597 generic form, so that the UDP server here sends their
// octets without the zone handlers. The auth client presents them by
// type, which only the zone handlers encode. tests/jest.setup.ts
// registers every handler, so the modules are loaded afresh in an
// isolated registry where only what each test registers exists.

import * as dgram from 'dgram';
import * as fs from 'fs';
import * as path from 'path';
import type * as HandlersModule from '../../src/dnssec/handlers';
import type * as RootAnchorsModule from '../../src/dnssec/root_anchors';
import type * as AuthModule from '../../src/resolver/auth';
import type * as MemoryModule from '../../src/resolver/memory';
import type * as VerdictModule from '../../src/verifier/verdict';
import type * as VerifierModule from '../../src/verifier/verifier';
import type * as MessageModule from '../../src/wire/dns_message';
import type * as WireModule from '../../src/wire/dns_wire';
import type * as WireUtilModule from '../../src/wire/dns_wire_util';
import type * as ZoneModule from '../../src/zone/dns_zone';
import type * as ZoneHandlersModule from '../../src/zone/handlers';
import type * as RegistryModule from '../../src/zone/registry';
import type * as ErrorsModule from '../../src/verifier/errors';

const handlersDir = path.join(__dirname, '..', 'testdata', 'handlers');
const clock = new Date('2026-06-01T00:00:00Z');

// ZONE_HANDLER_ANSWERS are the zone-handler-type records of
// testdata/handlers, in presentation form.
const ZONE_HANDLER_ANSWERS = [
    ['svc.example.test.', 64, '1 target.example.'],
    ['www.example.test.', 65, '1 . alpn=h2'],
    ['_443._tcp.www.example.test.', 52, '3 1 1 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'],
    ['x._smimecert.example.test.', 53, '3 0 1 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'],
] as const;

const TYPE_NAMES: Readonly<Record<number, string>> = { 52: 'TLSA', 53: 'SMIMEA', 64: 'SVCB', 65: 'HTTPS' };

function read(name: string): string {
    return fs.readFileSync(path.join(handlersDir, name), 'utf8');
}

interface Isolated {
    handlers: typeof HandlersModule;
    anchors: typeof RootAnchorsModule;
    auth: typeof AuthModule;
    memory: typeof MemoryModule;
    verdict: typeof VerdictModule;
    verifier: typeof VerifierModule;
    message: typeof MessageModule;
    wire: typeof WireModule;
    wireUtil: typeof WireUtilModule;
    zone: typeof ZoneModule;
    zoneHandlers: typeof ZoneHandlersModule;
    registry: typeof RegistryModule;
    errors: typeof ErrorsModule;
}

function loadIsolated(): Isolated {
    let mods: Isolated | undefined;
    jest.isolateModules(() => {
        mods = {
            handlers: require('../../src/dnssec/handlers'),
            anchors: require('../../src/dnssec/root_anchors'),
            auth: require('../../src/resolver/auth'),
            memory: require('../../src/resolver/memory'),
            verdict: require('../../src/verifier/verdict'),
            verifier: require('../../src/verifier/verifier'),
            message: require('../../src/wire/dns_message'),
            wire: require('../../src/wire/dns_wire'),
            wireUtil: require('../../src/wire/dns_wire_util'),
            zone: require('../../src/zone/dns_zone'),
            zoneHandlers: require('../../src/zone/handlers'),
            registry: require('../../src/zone/registry'),
            errors: require('../../src/verifier/errors'),
        };
    });
    if (mods === undefined) throw new Error('isolateModules did not run');
    return mods;
}

// answer_query builds the wire response of authority to query. The
// generic-form records go out as their octets; the DNSSEC records use
// the DNSSEC handlers the test registered.
async function answer_query(m: Isolated, authority: MemoryModule.Authority, query: Uint8Array): Promise<Uint8Array> {
    const q = m.message.parse_message(query).question;
    const resp = await authority.query(q.name, q.type);
    const b = new m.wireUtil.WireBuilder();
    b.append_uint16((query[0] << 8) | query[1]);
    b.append_uint16(0x8400 | resp.rcode); // QR, AA
    b.append_uint16(1);
    b.append_uint16(resp.records.length); // every record in the answer section
    b.append_uint16(0);
    b.append_uint16(0);
    b.append_bytes(m.wire.domain_name2wire(q.name));
    b.append_uint16(q.type);
    b.append_uint16(q.class);
    for (const rr of resp.records) {
        rr.get_wire_header(b);
        b.append_uint32(rr.ttl);
        rr.get_wire_body(b);
    }
    return b.build();
}

function serve_udp(m: Isolated, authority: MemoryModule.Authority): Promise<{ addr: string; close: () => void }> {
    return new Promise((resolve, reject) => {
        const socket = dgram.createSocket('udp4');
        socket.once('error', reject);
        socket.on('message', (msg, rinfo) => {
            void answer_query(m, authority, new Uint8Array(msg)).then((resp) => socket.send(resp, rinfo.port, rinfo.address));
        });
        socket.once('listening', () => {
            const a = socket.address();
            resolve({ addr: `${a.address}:${a.port}`, close: () => socket.close() });
        });
        socket.bind(0, '127.0.0.1');
    });
}

function read_zone(m: Isolated, text: string): ZoneModule.Zone {
    const z = new m.zone.Zone();
    z.read_string(text);
    return z;
}

describe('answers that need the zone handlers (testdata/handlers)', () => {
    const m = loadIsolated();
    const anchors = m.anchors.parseRootAnchors(read('root-anchors.json'));
    const authority = m.memory.new_authority(m.memory.with_zone('.', read_zone(m, read('root.zone'))));
    let server: { addr: string; close: () => void };

    beforeAll(async () => {
        server = await serve_udp(m, authority);
    });
    afterAll(() => server.close());

    it('the constructor registers no handler', () => {
        new m.verifier.Verifier({ resolver: authority, trustAnchors: anchors });
        expect([48, 46, 52, 53, 64, 65].map((t) => m.zone.has_encoder(t))).toEqual([false, false, false, false, false, false]);
    });

    it.each(ZONE_HANDLER_ANSWERS)('%s/%d received over UDP is secure with only the DNSSEC handlers', async (qname, qtype, value) => {
        m.handlers.register_dnssec_handlers();
        const client = new m.auth.AuthClient({ servers: [server.addr], timeout_ms: 2000 });
        const resolver = { query: (name: string, t: number, signal?: AbortSignal) => client.resolve(name, t, signal) };
        const v = new m.verifier.Verifier({ resolver, trustAnchors: anchors, now: () => clock });
        const res = await v.validate(qname, qtype);
        expect(`${res.verdict} ${res.bogusReason ?? ''}`).toBe(`${m.verdict.Verdict.Secure} `);
        expect(res.answer?.records.map((r) => r.value)).toEqual([value]);
        expect([52, 53, 64, 65].map((t) => m.zone.has_encoder(t))).toEqual([false, false, false, false]);
    });

    // A record held in presentation form without its octets (a cache
    // that rebuilt it) fails with an error naming the registration.
    it('a record without an encoder names the registration it needs', async () => {
        m.handlers.register_dnssec_handlers();
        const v = new m.verifier.Verifier({ resolver: presented_authority(m), trustAnchors: anchors, now: () => clock });
        await expect(v.validate('svc.example.test.', 64)).rejects.toThrow(/VerifierOptions\.zoneHandlers/);
    });

    // Records an in-memory authority returns in presentation form
    // without their octets validate with the zone handlers in the
    // Verifier's own registry: through zoneHandlers, and through a
    // registry with both handler sets. The default registry is left
    // without them.
    describe.each(['zoneHandlers', 'registry'] as const)('presented answers with %s', (how) => {
        it.each(ZONE_HANDLER_ANSWERS)('%s/%d is secure', async (qname, qtype, value) => {
            m.handlers.register_dnssec_handlers();
            const opts = { resolver: presented_authority(m), trustAnchors: anchors, now: () => clock };
            const v = how === 'zoneHandlers'
                ? new m.verifier.Verifier({ ...opts, zoneHandlers: true })
                : new m.verifier.Verifier({ ...opts, registry: both_registry(m) });
            const res = await v.validate(qname, qtype);
            expect(`${res.verdict} ${res.bogusReason ?? ''}`).toBe(`${m.verdict.Verdict.Secure} `);
            expect(res.answer?.records.map((r) => r.value)).toEqual([value]);
            expect([52, 53, 64, 65].map((t) => m.zone.has_encoder(t))).toEqual([false, false, false, false]);
        });
    });

    it('zoneHandlers and registry together are a configuration error', () => {
        expect(() => new m.verifier.Verifier({ resolver: authority, registry: new m.registry.Registry(), zoneHandlers: true }))
            .toThrow(m.errors.VerifierConfigError);
    });
});

// presented_authority serves the signed zone of testdata/handlers with
// its zone-handler-type records in presentation form, as an in-memory
// authority returns records it holds as text (no RDATA octets).
function presented_authority(m: Isolated): MemoryModule.Authority {
    const text = read('root.zone').split('\n').map((line) => {
        for (const [qname, qtype, value] of ZONE_HANDLER_ANSWERS) {
            const prefix = `${qname} 3600 IN ${TYPE_NAMES[qtype]} `;
            if (line.startsWith(prefix)) return prefix + value;
        }
        return line;
    }).join('\n');
    return m.memory.new_authority(m.memory.with_zone('.', read_zone(m, text)));
}

// both_registry returns a registry holding the DNSSEC and zone handlers.
function both_registry(m: Isolated): RegistryModule.Registry {
    const registry = new m.registry.Registry();
    m.handlers.register_dnssec_handlers_into(registry);
    m.zoneHandlers.register_legacy_handlers_into(registry);
    return registry;
}
