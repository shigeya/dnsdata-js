// DNSSecZone tests

import * as crypto from 'crypto';
import { DNSSecZone, KeyVerifyMode } from "../../src/dnssec/dnssec_zone";
import { DNSKey, DNSRR_DS } from "../../src/dnssec/dnssec_rr";

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

    it("uses any-valid semantics: valid RRSIG + bogus RRSIG still verifies", () => {
        const { zone } = create_test_zone();

        // Add a bogus RRSIG for the A record (random signature data)
        const bogus_sig = Buffer.from(new Uint8Array(128)).toString('base64');
        const rrsigs = zone.find_rrsigs("example.com.", 1);
        expect(rrsigs.length).toBe(1);

        // Add a second RRSIG with garbage signature but matching key_tag/signer
        const bogus_value = `A ${rrsigs[0].algorithm} ${rrsigs[0].labels} ` +
            `3600 2000000000 1000000000 ${rrsigs[0].key_tag} ${rrsigs[0].signer} ${bogus_sig}`;
        zone.add_rr_from_parts("example.com.", 3600, "IN", "RRSIG", bogus_value);

        // Should still pass because the valid RRSIG exists (any-valid)
        expect(zone.verify_rrset("example.com.", 1)).toBe(true);
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

    it("verify_delegation_signer_with_ds supports SHA-1 (digest type 1)", () => {
        const { zone, keyTag } = create_test_zone();
        const dnskey = zone.find_dnskey("example.com.", keyTag)!;

        const ds_input = dnskey.get_ds_digest_data();
        const hash = crypto.createHash('sha1').update(Buffer.from(ds_input)).digest();
        const hex_digest = Buffer.from(hash).toString('hex');

        const ds = new DNSRR_DS(null as any, `${keyTag} ${dnskey.algorithm} 1 ${hex_digest}`);
        expect(zone.verify_delegation_signer_with_ds(dnskey, ds)).toBe(true);
    });

    it("verify_delegation_signer_with_ds supports SHA-384 (digest type 4)", () => {
        const { zone, keyTag } = create_test_zone();
        const dnskey = zone.find_dnskey("example.com.", keyTag)!;

        const ds_input = dnskey.get_ds_digest_data();
        const hash = crypto.createHash('sha384').update(Buffer.from(ds_input)).digest();
        const hex_digest = Buffer.from(hash).toString('hex');

        const ds = new DNSRR_DS(null as any, `${keyTag} ${dnskey.algorithm} 4 ${hex_digest}`);
        expect(zone.verify_delegation_signer_with_ds(dnskey, ds)).toBe(true);
    });
});

// Helper: create a parent-child zone pair with DS in parent
function create_parent_child_zones(): {
    parentZone: DNSSecZone,
    childZone: DNSSecZone,
    parentKeyTag: number,
    childKeyTag: number,
} {
    // Generate parent key (RSA)
    const parentKP = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const parentJwk = parentKP.publicKey.export({ format: 'jwk' } as any) as any;
    const parentN = Buffer.from(parentJwk.n, 'base64url');
    const parentE = Buffer.from(parentJwk.e, 'base64url');
    const parentRfc3110 = Buffer.concat([Buffer.from([parentE.length]), parentE, parentN]);
    const parentKeyB64 = parentRfc3110.toString('base64');

    // Generate child key (RSA)
    const childKP = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const childJwk = childKP.publicKey.export({ format: 'jwk' } as any) as any;
    const childN = Buffer.from(childJwk.n, 'base64url');
    const childE = Buffer.from(childJwk.e, 'base64url');
    const childRfc3110 = Buffer.concat([Buffer.from([childE.length]), childE, childN]);
    const childKeyB64 = childRfc3110.toString('base64');

    // --- Parent zone ---
    const parentZone = new DNSSecZone();
    parentZone.add_rr_from_parts("com.", 3600, "IN", "SOA",
        "ns1.com. admin.com. 2021010101 3600 900 604800 86400");
    parentZone.add_rr_from_parts("com.", 3600, "IN", "DNSKEY", `257 3 8 ${parentKeyB64}`);
    parentZone.add_sep("com.");

    const parentDnskeyRR = parentZone.find_rr("com.", 48)!;
    const parentDnskey = parentDnskeyRR.get_handler() as DNSKey;
    parentDnskey.set_private_key(parentKP.privateKey);

    // Sign parent DNSKEY
    const parentDnskeyRrsig = parentZone.sign_rr("com.", 3600, 48, parentDnskey, 1000000000, 2000000000);
    if (parentDnskeyRrsig) parentZone.add_rr(parentDnskeyRrsig);

    // --- Child zone ---
    const childZone = new DNSSecZone();
    childZone.add_rr_from_parts("example.com.", 3600, "IN", "SOA",
        "ns1.example.com. admin.example.com. 2021010101 3600 900 604800 86400");
    childZone.add_rr_from_parts("example.com.", 3600, "IN", "A", "93.184.216.34");
    childZone.add_rr_from_parts("example.com.", 3600, "IN", "DNSKEY", `257 3 8 ${childKeyB64}`);

    const childDnskeyRR = childZone.find_rr("example.com.", 48)!;
    const childDnskey = childDnskeyRR.get_handler() as DNSKey;
    childDnskey.set_private_key(childKP.privateKey);

    // Sign child DNSKEY (self-signed by child KSK)
    const childDnskeyRrsig = childZone.sign_rr("example.com.", 3600, 48, childDnskey, 1000000000, 2000000000);
    if (childDnskeyRrsig) childZone.add_rr(childDnskeyRrsig);

    // Sign child A record
    const aRrsig = childZone.sign_rr("example.com.", 3600, 1, childDnskey, 1000000000, 2000000000);
    if (aRrsig) childZone.add_rr(aRrsig);

    // Compute DS for child KSK and add to parent zone
    const dsInput = childDnskey.get_ds_digest_data();
    const dsHash = crypto.createHash('sha256').update(Buffer.from(dsInput)).digest();
    const dsHex = Buffer.from(dsHash).toString('hex');
    const dsValue = `${childDnskey.key_tag} ${childDnskey.algorithm} 2 ${dsHex}`;
    parentZone.add_rr_from_parts("example.com.", 3600, "IN", "DS", dsValue);

    // Sign DS RRset with parent key
    const dsRrsig = parentZone.sign_rr("example.com.", 3600, 43, parentDnskey, 1000000000, 2000000000); // DS=43
    if (dsRrsig) parentZone.add_rr(dsRrsig);

    // Link child to parent
    childZone.parent = parentZone;

    return {
        parentZone,
        childZone,
        parentKeyTag: parentDnskey.key_tag,
        childKeyTag: childDnskey.key_tag,
    };
}

describe("DNSSecZone parent zone", () => {
    it("verify_delegation_signer with parent zone finds DS in parent", () => {
        const { childZone, childKeyTag } = create_parent_child_zones();
        const childDnskey = childZone.find_dnskey("example.com.", childKeyTag)!;
        // DS is in parent zone, child zone has parent set
        expect(childZone.verify_delegation_signer(childDnskey)).toBe(true);
    });

    it("verify_delegation_signer falls back to self when no parent", () => {
        const { zone, keyTag } = create_test_zone();
        // No parent set, DS not in zone either, but SEP is set
        zone.add_sep("example.com.");
        const dnskey = zone.find_dnskey("example.com.", keyTag)!;
        expect(zone.verify_delegation_signer(dnskey)).toBe(true);
    });

    it("verify_delegation_signer fails when DS is only in parent but parent not set", () => {
        const { childZone, childKeyTag } = create_parent_child_zones();
        // Unlink parent
        childZone.parent = null;
        const childDnskey = childZone.find_dnskey("example.com.", childKeyTag)!;
        // DS only exists in parentZone, not in childZone, so should fail
        expect(childZone.verify_delegation_signer(childDnskey)).toBe(false);
    });

    it("verify_ds_rrset uses parent zone keys to verify DS RRSIG", () => {
        const { childZone } = create_parent_child_zones();
        // DS RRset in parent zone was signed by parent key
        expect(childZone.verify_ds_rrset("example.com.")).toBe(true);
    });

    it("verify_ds_rrset returns false when no parent set", () => {
        const { zone } = create_test_zone();
        expect(zone.verify_ds_rrset("example.com.")).toBe(false);
    });

    it("verify_rrset with KSK mode + parent: full chain verification", () => {
        const { childZone } = create_parent_child_zones();
        // KSK mode: verify_ksk -> verify_delegation_signer -> finds DS in parent
        // Then verify DNSKEY RRSIG
        expect(childZone.verify_rrset("example.com.", 48, KeyVerifyMode.KSK)).toBe(true);
    });

    it("parent getter/setter works correctly", () => {
        const zone1 = new DNSSecZone();
        const zone2 = new DNSSecZone();
        expect(zone1.parent).toBeNull();
        zone1.parent = zone2;
        expect(zone1.parent).toBe(zone2);
        zone1.parent = null;
        expect(zone1.parent).toBeNull();
    });
});

describe("DNSSecZone signing", () => {
    it("can sign and then verify an RRset", () => {
        const { zone } = create_test_zone();
        // The A record was already signed in create_test_zone
        // Verify it
        const result = zone.verify_rrset("example.com.", 1);
        expect(result).toBe(true);
    });
});

describe("DNSSecZone ECDSA P-256 (algorithm 13)", () => {
    it("can sign and verify with ECDSA P-256 key", () => {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
        const jwk = publicKey.export({ format: 'jwk' } as any) as any;

        const x = Buffer.from(jwk.x, 'base64url');
        const y = Buffer.from(jwk.y, 'base64url');
        const key_data = Buffer.concat([x, y]);
        const key_b64 = key_data.toString('base64');

        const zone = new DNSSecZone();
        zone.add_rr_from_parts("example.com.", 3600, "IN", "SOA",
            "ns1.example.com. admin.example.com. 2021010101 3600 900 604800 86400");
        zone.add_rr_from_parts("example.com.", 3600, "IN", "A", "93.184.216.34");

        const dnskey_value = `257 3 13 ${key_b64}`;
        zone.add_rr_from_parts("example.com.", 3600, "IN", "DNSKEY", dnskey_value);

        const dnskey_rr = zone.find_rr("example.com.", 48)!;
        const dnskey = dnskey_rr.get_handler() as DNSKey;
        dnskey.set_private_key(privateKey);

        // Sign A record
        const rrsig_rr = zone.sign_rr("example.com.", 3600, 1, dnskey, 1000000000, 2000000000);
        expect(rrsig_rr).not.toBeNull();
        zone.add_rr(rrsig_rr!);

        // Verify
        expect(zone.verify_rrset("example.com.", 1)).toBe(true);
    });
});

describe("DNSSecZone Ed25519 (algorithm 15)", () => {
    it("can sign and verify with Ed25519 key", () => {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
        const jwk = publicKey.export({ format: 'jwk' } as any) as any;
        const key_data = Buffer.from(jwk.x, 'base64url');
        const key_b64 = key_data.toString('base64');

        const zone = new DNSSecZone();
        zone.add_rr_from_parts("example.com.", 3600, "IN", "SOA",
            "ns1.example.com. admin.example.com. 2021010101 3600 900 604800 86400");
        zone.add_rr_from_parts("example.com.", 3600, "IN", "A", "93.184.216.34");

        const dnskey_value = `257 3 15 ${key_b64}`;
        zone.add_rr_from_parts("example.com.", 3600, "IN", "DNSKEY", dnskey_value);

        const dnskey_rr = zone.find_rr("example.com.", 48)!;
        const dnskey = dnskey_rr.get_handler() as DNSKey;
        dnskey.set_private_key(privateKey);

        const rrsig_rr = zone.sign_rr("example.com.", 3600, 1, dnskey, 1000000000, 2000000000);
        expect(rrsig_rr).not.toBeNull();
        zone.add_rr(rrsig_rr!);

        expect(zone.verify_rrset("example.com.", 1)).toBe(true);
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
