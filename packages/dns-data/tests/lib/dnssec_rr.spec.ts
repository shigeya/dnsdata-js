// DNSSEC Resource Record tests

import { DNSKey, RRSig, DNSRR_DS } from "../../src/lib/dnssec_rr";
import { ResourceRecord } from "../../src/lib/dns_zone";
import { WireBuilder } from "../../src/lib/dns_wire_util";

describe("DNSKey", () => {
    // Example DNSKEY from RFC4034 style
    const dnskey_value = "257 3 5 AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8nokfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6zMv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1UaNvv4w==";
    const dnskey_rr = new ResourceRecord("example.net.", 3600, "IN", "DNSKEY", dnskey_value);

    it("can parse DNSKEY presentation format", () => {
        const key = new DNSKey(dnskey_rr, dnskey_value);
        expect(key.flags).toBe(257);
        expect(key.protocol).toBe(3);
        expect(key.algorithm).toBe(5);
        expect(key.key_data.length).toBeGreaterThan(0);
    });

    it("computes key tag correctly", () => {
        const key = new DNSKey(dnskey_rr, dnskey_value);
        // Key tag should be a 16-bit value
        expect(key.key_tag).toBeGreaterThan(0);
        expect(key.key_tag).toBeLessThan(65536);
    });

    it("identifies KSK vs ZSK", () => {
        const ksk = new DNSKey(dnskey_rr, "257 3 5 AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8nokfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6zMv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1UaNvv4w==");
        expect(ksk.is_zone_key()).toBe(true);
        expect(ksk.is_secure_entry_point()).toBe(true);

        const zsk_value = "256 3 5 AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8nokfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6zMv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1UaNvv4w==";
        const zsk = new DNSKey(dnskey_rr, zsk_value);
        expect(zsk.is_zone_key()).toBe(true);
        expect(zsk.is_secure_entry_point()).toBe(false);
    });

    it("builds wire body correctly", () => {
        const key = new DNSKey(dnskey_rr, dnskey_value);
        const wb = new WireBuilder();
        key.get_wire_body(wb);
        const result = wb.build();
        // rdlen(2) + flags(2) + proto(1) + algo(1) + keydata
        expect(result.length).toBe(2 + 4 + key.key_data.length);
        // Check flags in wire format
        expect(result[2]).toBe(0x01); // flags high byte (257 = 0x0101)
        expect(result[3]).toBe(0x01); // flags low byte
        expect(result[4]).toBe(3);    // protocol
        expect(result[5]).toBe(5);    // algorithm
    });

    it("builds DS digest data correctly", () => {
        const key = new DNSKey(dnskey_rr, dnskey_value);
        const data = key.get_ds_digest_data();
        // Should start with wire-format owner name
        // example.net. = \x07example\x03net\x00
        expect(data[0]).toBe(7);  // length of "example"
        expect(data.length).toBeGreaterThan(12 + key.key_data.length);
    });

    it("can load RSA public key and verify would not crash", () => {
        const key = new DNSKey(dnskey_rr, dnskey_value);
        // Just verify that key loading doesn't throw
        expect(() => key.get_public_key()).not.toThrow();
    });

    it("generates ISC key base filename", () => {
        const key = new DNSKey(dnskey_rr, dnskey_value);
        const fn = key.get_isc_key_base_filename();
        expect(fn).toMatch(/^Kexample\.net\.\+005\+\d{5}$/);
    });
});

describe("RRSig", () => {
    const rrsig_value = "A 5 3 86400 20121201000000 20121101000000 12345 example.com. dGVzdHNpZ25hdHVyZQ==";
    const rrsig_rr = new ResourceRecord("www.example.com.", 86400, "IN", "RRSIG", rrsig_value);

    it("can parse RRSIG presentation format", () => {
        const sig = new RRSig(rrsig_rr, rrsig_value);
        expect(sig.type_covered).toBe(1); // A
        expect(sig.algorithm).toBe(5);
        expect(sig.labels).toBe(3);
        expect(sig.original_ttl).toBe(86400);
        expect(sig.key_tag).toBe(12345);
        expect(sig.signer).toBe("example.com.");
        expect(sig.signature.length).toBeGreaterThan(0);
    });

    it("parses datetime strings correctly", () => {
        // 20121201000000 = 2012-12-01 00:00:00 UTC
        const ts = RRSig.datetime_str_to_int("20121201000000");
        expect(ts).toBe(Math.floor(Date.UTC(2012, 11, 1, 0, 0, 0) / 1000));

        // Plain integer
        expect(RRSig.datetime_str_to_int("1354320000")).toBe(1354320000);
    });

    it("builds RDATA digest target (without signature)", () => {
        const sig = new RRSig(rrsig_rr, rrsig_value);
        const dt = sig.get_rdata_digest_target();
        // type_covered(2) + algo(1) + labels(1) + orig_ttl(4) + expire(4) + inception(4) + keytag(2) + signer_wire
        expect(dt[0]).toBe(0x00); // type covered high
        expect(dt[1]).toBe(0x01); // type covered low (A=1)
        expect(dt[2]).toBe(5);    // algorithm
        expect(dt[3]).toBe(3);    // labels
    });

    it("builds full wire body with rdlen", () => {
        const sig = new RRSig(rrsig_rr, rrsig_value);
        const wb = new WireBuilder();
        sig.get_wire_body(wb);
        const result = wb.build();
        // Should start with rdlen(2)
        const rdlen = (result[0] << 8) | result[1];
        expect(rdlen).toBe(result.length - 2);
    });

    it("generates value string", () => {
        const sig = new RRSig(rrsig_rr, rrsig_value);
        const vs = sig.get_value_string();
        expect(vs).toContain("A 5 3 86400");
        expect(vs).toContain("example.com.");
    });
});

describe("DNSRR_DS", () => {
    const ds_value = "12345 5 2 " + "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const ds_rr = new ResourceRecord("example.com.", 3600, "IN", "DS", ds_value);

    it("can parse DS presentation format", () => {
        const ds = new DNSRR_DS(ds_rr, ds_value);
        expect(ds.key_tag).toBe(12345);
        expect(ds.algorithm).toBe(5);
        expect(ds.digest_type).toBe(2);
        expect(ds.digest.length).toBe(32); // SHA-256 = 32 bytes
    });

    it("builds wire body correctly", () => {
        const ds = new DNSRR_DS(ds_rr, ds_value);
        const wb = new WireBuilder();
        ds.get_wire_body(wb);
        const result = wb.build();
        // rdlen(2) + keytag(2) + algo(1) + digesttype(1) + digest(32)
        expect(result.length).toBe(2 + 4 + 32);
        const rdlen = (result[0] << 8) | result[1];
        expect(rdlen).toBe(4 + 32);
    });

    it("can verify a DS digest", () => {
        // Create a DNSKey, compute its DS digest, then verify
        const key_value = "257 3 5 AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8nokfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6zMv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1UaNvv4w==";
        const key_rr = new ResourceRecord("example.com.", 3600, "IN", "DNSKEY", key_value);
        const key = new DNSKey(key_rr, key_value);

        // Compute the DS digest data
        const ds_input = key.get_ds_digest_data();

        // Compute SHA-256 hash
        const crypto = require('crypto');
        const hash = crypto.createHash('sha256').update(Buffer.from(ds_input)).digest();
        const hex_digest = Buffer.from(hash).toString('hex');

        // Create a DS record with this digest
        const ds_val = `${key.key_tag} ${key.algorithm} 2 ${hex_digest}`;
        const ds = new DNSRR_DS(null as any, ds_val);
        expect(ds.verify_digest(ds_input)).toBe(true);

        // Tampered digest should fail
        const bad_ds_val = `${key.key_tag} ${key.algorithm} 2 ${"00".repeat(32)}`;
        const bad_ds = new DNSRR_DS(null as any, bad_ds_val);
        expect(bad_ds.verify_digest(ds_input)).toBe(false);
    });
});

describe("DNSKey ECDSA P-256 (algorithm 13)", () => {
    it("can parse ECDSA P-256 DNSKEY", () => {
        // Generate an EC P-256 key pair and create a DNSKEY
        const crypto = require('crypto');
        const { publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
        const jwk = publicKey.export({ format: 'jwk' } as any) as any;

        // DNSSEC stores x||y (64 bytes for P-256)
        const x = Buffer.from(jwk.x, 'base64url');
        const y = Buffer.from(jwk.y, 'base64url');
        const key_data = Buffer.concat([x, y]);
        const key_b64 = key_data.toString('base64');

        const value = `257 3 13 ${key_b64}`;
        const rr = new ResourceRecord("example.com.", 3600, "IN", "DNSKEY", value);
        const key = new DNSKey(rr, value);
        expect(key.algorithm).toBe(13);
        expect(key.key_data.length).toBe(64);
        expect(key.key_tag).toBeGreaterThan(0);
    });

    it("can load ECDSA public key and verify signature", () => {
        const crypto = require('crypto');
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
        const jwk = publicKey.export({ format: 'jwk' } as any) as any;

        const x = Buffer.from(jwk.x, 'base64url');
        const y = Buffer.from(jwk.y, 'base64url');
        const key_data = Buffer.concat([x, y]);
        const key_b64 = key_data.toString('base64');

        const value = `257 3 13 ${key_b64}`;
        const rr = new ResourceRecord("example.com.", 3600, "IN", "DNSKEY", value);
        const dnskey = new DNSKey(rr, value);
        dnskey.set_private_key(privateKey);

        const test_data = new Uint8Array([1, 2, 3, 4, 5]);
        const signature = dnskey.sign(test_data);
        expect(signature.length).toBe(64); // P-256: r(32) + s(32)
        expect(dnskey.verify(test_data, signature)).toBe(true);
    });
});

describe("DNSKey Ed25519 (algorithm 15)", () => {
    it("can parse Ed25519 DNSKEY and sign/verify", () => {
        const crypto = require('crypto');
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
        const jwk = publicKey.export({ format: 'jwk' } as any) as any;

        // Ed25519 public key is 32 bytes raw
        const key_data = Buffer.from(jwk.x, 'base64url');
        expect(key_data.length).toBe(32);
        const key_b64 = key_data.toString('base64');

        const value = `257 3 15 ${key_b64}`;
        const rr = new ResourceRecord("example.com.", 3600, "IN", "DNSKEY", value);
        const dnskey = new DNSKey(rr, value);
        expect(dnskey.algorithm).toBe(15);
        expect(dnskey.key_data.length).toBe(32);

        dnskey.set_private_key(privateKey);

        const test_data = new Uint8Array([1, 2, 3, 4, 5]);
        const signature = dnskey.sign(test_data);
        expect(signature.length).toBe(64); // Ed25519 signature is 64 bytes
        expect(dnskey.verify(test_data, signature)).toBe(true);
    });
});

describe("Handler registration", () => {
    it("ResourceRecord.get_handler() returns DNSKey for DNSKEY records", () => {
        const rr = new ResourceRecord("example.com.", 3600, "IN", "DNSKEY",
            "257 3 5 AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8nokfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6zMv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1UaNvv4w==");
        const handler = rr.get_handler();
        expect(handler).toBeInstanceOf(DNSKey);
    });

    it("ResourceRecord.get_handler() returns RRSig for RRSIG records", () => {
        const rr = new ResourceRecord("www.example.com.", 86400, "IN", "RRSIG",
            "A 5 3 86400 20121201000000 20121101000000 12345 example.com. dGVzdHNpZ25hdHVyZQ==");
        const handler = rr.get_handler();
        expect(handler).toBeInstanceOf(RRSig);
    });

    it("ResourceRecord.get_handler() returns DNSRR_DS for DS records", () => {
        const rr = new ResourceRecord("example.com.", 3600, "IN", "DS",
            "12345 5 2 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
        const handler = rr.get_handler();
        expect(handler).toBeInstanceOf(DNSRR_DS);
    });
});
