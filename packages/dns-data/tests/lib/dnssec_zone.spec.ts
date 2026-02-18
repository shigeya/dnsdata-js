// DNSSecZone tests

import * as crypto from 'crypto';
import { DNSSecZone, KeyVerifyMode } from "../../src/lib/dnssec_zone";
import { DNSKey, RRSig, DNSRR_DS } from "../../src/lib/dnssec_rr";
import { ResourceRecord } from "../../src/lib/dns_zone";

// Generate a test RSA key pair and create a signed zone for testing
function create_test_zone(): {
    zone: DNSSecZone,
    privateKey: crypto.KeyObject,
    publicKey: crypto.KeyObject,
    keyTag: number
} {
    // Generate RSA key pair
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
    });

    // Export public key as JWK to extract n and e
    const jwk = publicKey.export({ format: 'jwk' } as any) as any;
    const n = Buffer.from(jwk.n, 'base64url');
    const e = Buffer.from(jwk.e, 'base64url');

    // Build RFC3110 format: exponent_length(1) + exponent + modulus
    const rfc3110 = Buffer.concat([
        Buffer.from([e.length]),
        e,
        n,
    ]);
    const key_b64 = rfc3110.toString('base64');

    // Create zone
    const zone = new DNSSecZone();

    // Add SOA
    zone.add_rr_from_parts("example.com.", 3600, "IN", "SOA",
        "ns1.example.com. admin.example.com. 2021010101 3600 900 604800 86400");

    // Add A record
    zone.add_rr_from_parts("example.com.", 3600, "IN", "A", "93.184.216.34");

    // Add DNSKEY (KSK, flags=257)
    const dnskey_value = `257 3 8 ${key_b64}`;
    zone.add_rr_from_parts("example.com.", 3600, "IN", "DNSKEY", dnskey_value);

    // Get the key tag
    const dnskey_rr = zone.find_rr("example.com.", 48)!; // DNSKEY=48
    const dnskey = dnskey_rr.get_handler() as DNSKey;
    dnskey.set_private_key(privateKey);

    // Now create RRSIG for the A record
    const a_rrsig_rr = zone.sign_rr("example.com.", 3600, 1, dnskey, 1000000000, 2000000000);
    if (a_rrsig_rr) zone.add_rr(a_rrsig_rr);

    // Create RRSIG for the DNSKEY record (self-signed by KSK)
    const dnskey_rrsig_rr = zone.sign_rr("example.com.", 3600, 48, dnskey, 1000000000, 2000000000);
    if (dnskey_rrsig_rr) zone.add_rr(dnskey_rrsig_rr);

    return { zone, privateKey, publicKey, keyTag: dnskey.key_tag };
}

describe("DNSSecZone", () => {
    it("can find RRSIGs by name and type", () => {
        const { zone } = create_test_zone();
        const rrsigs = zone.find_rrsigs("example.com.", 1); // A=1
        expect(rrsigs.length).toBe(1);
        expect(rrsigs[0].type_covered).toBe(1);
    });

    it("can find DNSKEY by signer and key tag", () => {
        const { zone, keyTag } = create_test_zone();
        const key = zone.find_dnskey("example.com.", keyTag);
        expect(key).not.toBeNull();
        expect(key!.key_tag).toBe(keyTag);
    });

    it("returns null when DNSKEY not found", () => {
        const { zone } = create_test_zone();
        expect(zone.find_dnskey("notexist.com.")).toBeNull();
        expect(zone.find_dnskey("example.com.", 99999)).toBeNull();
    });

    it("can create digest target", () => {
        const { zone } = create_test_zone();
        const rrsigs = zone.find_rrsigs("example.com.", 1);
        expect(rrsigs.length).toBe(1);

        const dt = zone.create_digest_target(rrsigs[0], "example.com.", 1);
        expect(dt).not.toBeNull();
        expect(dt!.length).toBeGreaterThan(0);
    });

    it("can verify RRSIG on A record", () => {
        const { zone } = create_test_zone();
        const result = zone.verify_rrset("example.com.", 1); // A=1
        expect(result).toBe(true);
    });

    it("can verify RRSIG on DNSKEY record", () => {
        const { zone } = create_test_zone();
        const result = zone.verify_rrset("example.com.", 48); // DNSKEY=48
        expect(result).toBe(true);
    });

    it("fails verification for nonexistent record", () => {
        const { zone } = create_test_zone();
        expect(zone.verify_rrset("notexist.com.", 1)).toBe(false);
    });

    it("handles secure entry point", () => {
        const { zone } = create_test_zone();
        zone.add_sep("example.com.");
        expect(zone.is_secure_entry_point("example.com.")).toBe(true);
        expect(zone.is_secure_entry_point("other.com.")).toBe(false);
    });

    it("verify_delegation_signer returns true at trust anchor", () => {
        const { zone, keyTag } = create_test_zone();
        zone.add_sep("example.com.");
        const dnskey = zone.find_dnskey("example.com.", keyTag)!;
        expect(zone.verify_delegation_signer(dnskey)).toBe(true);
    });

    it("verify_delegation_signer_with_ds checks algorithm match and digest", () => {
        const { zone, keyTag } = create_test_zone();
        const dnskey = zone.find_dnskey("example.com.", keyTag)!;

        // Compute correct DS
        const ds_input = dnskey.get_ds_digest_data();
        const hash = crypto.createHash('sha256').update(Buffer.from(ds_input)).digest();
        const hex_digest = Buffer.from(hash).toString('hex');

        const ds = new DNSRR_DS(null as any, `${keyTag} ${dnskey.algorithm} 2 ${hex_digest}`);
        expect(zone.verify_delegation_signer_with_ds(dnskey, ds)).toBe(true);

        // Wrong algorithm should fail
        const bad_ds = new DNSRR_DS(null as any, `${keyTag} 99 2 ${hex_digest}`);
        expect(zone.verify_delegation_signer_with_ds(dnskey, bad_ds)).toBe(false);
    });
});

describe("DNSSecZone signing", () => {
    it("can sign and then verify an RRset", () => {
        const { zone, keyTag } = create_test_zone();
        // The A record was already signed in create_test_zone
        // Verify it
        const result = zone.verify_rrset("example.com.", 1);
        expect(result).toBe(true);
    });
});

describe("DNSSecZone zone file parsing", () => {
    it("can parse a zone with DNSKEY and RRSIG records", () => {
        const zone = new DNSSecZone();
        // Use a minimal zone text with DNSKEY
        const zone_text = `
example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2021010101 3600 900 604800 86400
example.com. 3600 IN NS ns1.example.com.
example.com. 3600 IN A 93.184.216.34
example.com. 3600 IN DNSKEY 257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=
`;
        zone.read_string(zone_text);

        expect(zone.find_rr("example.com.", 48)).not.toBeNull(); // DNSKEY
        const dnskey_rr = zone.find_rr("example.com.", 48)!;
        const handler = dnskey_rr.get_handler();
        expect(handler).toBeInstanceOf(DNSKey);
        expect((handler as DNSKey).flags).toBe(257);
        expect((handler as DNSKey).algorithm).toBe(8);
    });
});
