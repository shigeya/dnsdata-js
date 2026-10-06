// Registry tests. Ports dnsdata-go `zone/registry_test.go`.

import { StringToRRType } from '../../src/types/dns_type_table';
import { WireBuilder } from '../../src/wire/dns_wire_util';
import {
    Registry, ResourceRecord, ResourceRecordHandler, default_registry, has_encoder, register_rr_handler,
} from '../../src/zone/dns_zone';
import { register_legacy_handlers_into } from '../../src/zone/handlers';

// Types far outside the assigned range, distinct from the ones other
// handler tests register in the default registry.
const REG_TYPE_A = 65520;
const REG_TYPE_B = 65521;

class FakeHandler extends ResourceRecordHandler {
    constructor(rr: ResourceRecord | null, readonly text: string) { super(rr); }
    get_wire_body(builder: WireBuilder): void {
        const octets = Buffer.from(this.text, 'utf8');
        builder.append_uint16(octets.length);
        builder.append_bytes(octets);
    }
    clone(): ResourceRecordHandler { return new FakeHandler(this._rr, this.text); }
}

// OtherHandler is a second handler type, so a test can tell which
// registry's factory built a handler.
class OtherHandler extends FakeHandler {}

function fake_factory(calls: { n: number }) {
    return (rr: ResourceRecord, value: string): ResourceRecordHandler => {
        calls.n++;
        return new FakeHandler(rr, value);
    };
}

function other_factory(rr: ResourceRecord, value: string): ResourceRecordHandler {
    return new OtherHandler(rr, value + '!');
}

function new_rr(type: number, value: string): ResourceRecord {
    return new ResourceRecord('example.com.', 60, 'IN', type, value);
}

function wire_body(rr: ResourceRecord, registry?: Registry): Uint8Array {
    const b = new WireBuilder();
    rr.get_wire_body(b, registry);
    return b.build();
}

describe('Registry', () => {
    it('is isolated from the default registry', () => {
        const registry = new Registry();
        registry.register(REG_TYPE_A, fake_factory({ n: 0 }));

        expect(default_registry().lookup(REG_TYPE_A)).toBeUndefined();
        const rr = new_rr(REG_TYPE_A, 'hello');
        expect(rr.get_handler()).toBeNull();
        expect(rr.get_handler(registry)).toBeInstanceOf(FakeHandler);
        expect(has_encoder(REG_TYPE_A)).toBe(false);
        expect(has_encoder(REG_TYPE_A, registry)).toBe(true);
    });

    it('caches the handler per registry', () => {
        const calls = { n: 0 };
        const regA = new Registry();
        const regB = new Registry();
        regA.register(REG_TYPE_A, fake_factory(calls));
        regB.register(REG_TYPE_A, other_factory);
        const rr = new_rr(REG_TYPE_A, 'hello');

        const h = rr.get_handler(regA);
        expect(rr.get_handler(regA)).toBe(h);
        expect(calls.n).toBe(1);
        // A handler from regA must not leak to regB.
        expect(rr.get_handler(regB)).toBeInstanceOf(OtherHandler);
        const again = rr.get_handler(regA);
        expect(again).toBeInstanceOf(FakeHandler);
        expect(again).not.toBeInstanceOf(OtherHandler);
    });

    it('get_wire_body uses the registry given', () => {
        const registry = new Registry();
        registry.register(REG_TYPE_A, other_factory);
        const rr = new_rr(REG_TYPE_A, 'hi');

        expect(Buffer.from(wire_body(rr, registry).subarray(2)).toString('utf8')).toBe('hi!');
        expect(wire_body(rr).length).toBe(0);
    });

    it('register(type, null) removes the factory', () => {
        const registry = new Registry();
        registry.register(REG_TYPE_A, other_factory);
        registry.register(REG_TYPE_A, null);
        expect(registry.lookup(REG_TYPE_A)).toBeUndefined();
    });

    it('a missing registry means the default one', () => {
        register_rr_handler(REG_TYPE_B, other_factory);
        try {
            const rr = new_rr(REG_TYPE_B, 'x');
            expect(rr.get_handler()).toBe(rr.get_handler(default_registry()));
            expect(rr.get_handler()).toBeInstanceOf(OtherHandler);
        } finally {
            default_registry().register(REG_TYPE_B, null);
        }
    });

    it('register_legacy_handlers_into installs the zone handlers only', () => {
        const registry = new Registry();
        register_legacy_handlers_into(registry);
        expect(registry.lookup(StringToRRType('TLSA'))).toBeDefined();
        expect(registry.lookup(StringToRRType('SVCB'))).toBeDefined();
        expect(registry.lookup_rdata(StringToRRType('SVCB'))).toBeDefined();
        expect(registry.lookup(StringToRRType('DNSKEY'))).toBeUndefined();
    });
});
