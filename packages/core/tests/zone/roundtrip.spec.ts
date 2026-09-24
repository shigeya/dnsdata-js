// RFC 3597 generic RDATA and the shared RDATA round-trip vectors.
// Ports dnsdata-go zone/roundtrip_test.go. Handlers are registered by
// tests/jest.setup.ts.

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import {
    ResourceRecord,
    new_resource_record_from_rdata,
} from "../../src/zone/dns_zone";
import { parse_generic_rdata } from "../../src/zone/generic";
import { rdata_to_string, format_generic_rdata } from "../../src/wire/rdata_decoder";
import { WireBuilder } from "../../src/wire/dns_wire_util";
import { DNSRR_TLSA } from "../../src/zone/rr/dane_rr";
import { DNSRR_SVCB } from "../../src/zone/rr/svcb_rr";
import { DNSKey } from "../../src/dnssec/dnssec_rr";
import { DNSSecZone } from "../../src/dnssec/dnssec_zone";
import { DNSZonePresentationFormatError } from "../../src/dns_exception";

const CLASS_IN = 1;
const TYPE_A = 1;
const TYPE_TXT = 16;
const TYPE_RRSIG = 46;
const TYPE_DNSKEY = 48;
const TYPE_HTTPS = 65;
const TYPE_PRIVATE = 65400;
const SVC_KEY_ALPN = 1;

interface RDataVector {
    name: string;
    type: number;
    rdata: string;
}

function load_rdata_vectors(): RDataVector[] {
    const file = path.join(__dirname, '..', 'testdata', 'rdata_roundtrip.json');
    const doc = JSON.parse(fs.readFileSync(file, 'utf8')) as { vectors: RDataVector[] };
    return doc.vectors;
}

function hex_bytes(s: string): Uint8Array {
    return new Uint8Array(Buffer.from(s, 'hex'));
}

function to_hex(b: Uint8Array): string {
    return Buffer.from(b).toString('hex');
}

// Returns the RDATA octets (without RDLENGTH) of rr.
function wire_body_of(rr: ResourceRecord): Uint8Array {
    const builder = new WireBuilder();
    rr.get_wire_body(builder);
    const out = builder.build();
    expect(out.length).toBeGreaterThanOrEqual(2);
    expect((out[0] << 8) | out[1]).toBe(out.length - 2);
    return out.subarray(2);
}

// C-2 acceptance property: wire -> rdata_to_string -> ResourceRecord ->
// get_wire_body reproduces the RDATA, and so does the RFC 3597 generic
// form of the same octets.
describe("RDATA round trip", () => {
    const vectors = load_rdata_vectors();

    it("loads all shared vectors", () => {
        expect(vectors.length).toBe(33);
    });

    it.each(vectors.map(v => [v.name, v] as [string, RDataVector]))("%s", (_name, v) => {
        const rdata = hex_bytes(v.rdata);
        const pres = rdata_to_string(rdata, v.type, rdata, 0);
        for (const value of [pres, format_generic_rdata(rdata)]) {
            const rr = new ResourceRecord("example.com.", 300, CLASS_IN, v.type, value);
            expect({ value, wire: to_hex(wire_body_of(rr)) }).toEqual({ value, wire: v.rdata });
        }
    });
});

describe("parse_generic_rdata", () => {
    const ok: Array<[string, string]> = [
        ["\\# 4 0a000001", "0a000001"],
        ["\\# 4 0a00 0001", "0a000001"],
        ["\\# 0", ""],
    ];
    it.each(ok)("%s", (input, want) => {
        const got = parse_generic_rdata(input);
        expect(got).not.toBeNull();
        expect(to_hex(got!)).toBe(want);
    });

    const bad = ["\\# 3 0a000001", "\\# 4 0a0000zz", "\\#", "\\# x 00", "\\# 70000 00"];
    it.each(bad)("%s is an error", (input) => {
        expect(() => parse_generic_rdata(input)).toThrow(DNSZonePresentationFormatError);
    });

    it.each(["10.0.0.1", "\"\\# 4 0a000001\""])("%s is not generic", (input) => {
        expect(parse_generic_rdata(input)).toBeNull();
    });
});

describe("get_wire_body generic", () => {
    it("rejects a length mismatch", () => {
        const rr = new ResourceRecord("x.example.", 60, "IN", "TYPE65400", "\\# 5 00");
        expect(() => rr.get_wire_body(new WireBuilder())).toThrow(DNSZonePresentationFormatError);
    });
});

describe("get_handler from generic", () => {
    it("decodes TLSA", () => {
        const rr = new ResourceRecord("_443._tcp.example.", 60, "IN", "TLSA", "\\# 5 030101abcd");
        const h = rr.get_handler();
        expect(h).toBeInstanceOf(DNSRR_TLSA);
        const tlsa = h as DNSRR_TLSA;
        expect(tlsa.usage).toBe(3);
        expect(tlsa.selector).toBe(1);
        expect(tlsa.matching_type).toBe(1);
        expect(to_hex(tlsa.certificate_association_data)).toBe("abcd");
    });

    it("decodes SVCB / HTTPS", () => {
        const rr = new_resource_record_from_rdata("example.", 60, CLASS_IN, TYPE_HTTPS,
            hex_bytes("00010000010003026832"));
        const h = rr.get_handler();
        expect(h).toBeInstanceOf(DNSRR_SVCB);
        const svcb = h as DNSRR_SVCB;
        expect(svcb.priority).toBe(1);
        expect(svcb.target).toBe(".");
        expect(svcb.params.length).toBe(1);
        expect(svcb.params[0].key).toBe(SVC_KEY_ALPN);
    });

    it("decodes DNSKEY", () => {
        const rr = new_resource_record_from_rdata("example.", 60, CLASS_IN, TYPE_DNSKEY,
            hex_bytes("0101030d00010203"));
        expect(rr.get_handler()).toBeInstanceOf(DNSKey);
    });

    it("returns null for octets that do not decode", () => {
        const rr = new ResourceRecord("_443._tcp.example.", 60, "IN", "TLSA", "\\# 2 0301");
        expect(rr.get_handler()).toBeNull();
    });
});

describe("txt_strings", () => {
    it("reads generic and presentation values alike", () => {
        const generic = new_resource_record_from_rdata("example.", 60, CLASS_IN, TYPE_TXT,
            hex_bytes("0568656c6c6f00"));
        const pres = new ResourceRecord("example.", 60, "IN", "TXT", "\"hello\" \"\"");
        for (const rr of [generic, pres]) {
            expect(rr.txt_strings()).toEqual(["hello", ""]);
        }
    });

    it("rejects a non-TXT record", () => {
        const a = new ResourceRecord("example.", 60, "IN", "A", "192.0.2.1");
        expect(() => a.txt_strings()).toThrow();
    });

    it("rejects a truncated character-string", () => {
        const bad = new_resource_record_from_rdata("example.", 60, CLASS_IN, TYPE_TXT, hex_bytes("05ab"));
        expect(() => bad.txt_strings()).toThrow();
    });
});

describe("new_resource_record_from_rdata", () => {
    it("rejects RDATA over 65535 octets", () => {
        expect(() => new_resource_record_from_rdata("x.", 0, CLASS_IN, TYPE_PRIVATE, new Uint8Array(0x10000)))
            .toThrow();
    });
});

describe("to_string", () => {
    it("prints unknown type and class generically", () => {
        const rr = new ResourceRecord("x.example.", 60, "CLASS65280", "TYPE65400", "\\# 0");
        expect(rr.to_string()).toBe("x.example. 60 CLASS65280 TYPE65400 \\# 0");
    });
});

// sign_rr / verify_rrset on an RRset of a type without a mnemonic, and
// on an RRSIG held in generic form.
describe("DNSSecZone with an unknown type", () => {
    function signed_zone(): { zone: DNSSecZone; rrsig: ResourceRecord } {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
        const jwk = publicKey.export({ format: 'jwk' });
        const key_b64 = Buffer.from(jwk.x as string, 'base64url').toString('base64');

        const zone = new DNSSecZone();
        zone.add_rr(new_resource_record_from_rdata("example.com.", 3600, CLASS_IN, TYPE_PRIVATE,
            hex_bytes("030101000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")));
        zone.add_rr_from_parts("example.com.", 3600, "IN", "DNSKEY", `257 3 15 ${key_b64}`);
        const dnskey = zone.find_rr("example.com.", TYPE_DNSKEY)!.get_handler() as DNSKey;
        dnskey.set_private_key(privateKey);

        const rrsig = zone.sign_rr("example.com.", 3600, TYPE_PRIVATE, dnskey, 1000000000, 2000000000);
        expect(rrsig).not.toBeNull();
        return { zone, rrsig: rrsig! };
    }

    it("signs and verifies", () => {
        const { zone, rrsig } = signed_zone();
        expect(rrsig.value.startsWith("TYPE65400 15 ")).toBe(true);
        zone.add_rr(rrsig);
        expect(zone.verify_rrset("example.com.", TYPE_PRIVATE)).toBe(true);
    });

    it("verifies with the RRSIG in generic form", () => {
        const { zone, rrsig } = signed_zone();
        const generic = new_resource_record_from_rdata(rrsig.label, rrsig.ttl, CLASS_IN, TYPE_RRSIG,
            wire_body_of(rrsig));
        zone.add_rr(generic);
        expect(zone.verify_rrset("example.com.", TYPE_PRIVATE)).toBe(true);
        expect(zone.verify_rrset("example.com.", TYPE_A)).toBe(false);
    });
});
