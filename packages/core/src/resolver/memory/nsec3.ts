// A zone's NSEC3 records, for the proofs of RFC 5155 §7.2. Ports
// dnsdata-go `resolver/memory/nsec3.go`.

import { DNSRR_NSEC3, owner_hash_from_name } from '../../dnssec/nsec3';

// An NSEC3 record at owner, with the hash its owner label carries.
interface NSEC3Entry {
    readonly owner: string;
    readonly hash: Uint8Array;
    readonly nsec3: DNSRR_NSEC3;
}

// NSEC3Chain holds a zone's NSEC3 records. Names are hashed with the
// parameters of the first record; a signer uses one set per chain.
export class NSEC3Chain {
    private readonly entries: NSEC3Entry[] = [];

    // add parses the NSEC3 at owner; throws when it does not parse.
    add(owner: string, value: string): void {
        this.entries.push({ owner, hash: owner_hash_from_name(owner), nsec3: new DNSRR_NSEC3(null, value) });
    }

    // matching returns the owner of the NSEC3 whose hash is name's, or null.
    matching(name: string): string | null {
        const h = this.hash(name);
        if (h === null) return null;
        return this.entries.find((e) => Buffer.compare(e.hash, h) === 0)?.owner ?? null;
    }

    // covering returns the owner of the NSEC3 whose range covers name's
    // hash, or null.
    covering(name: string): string | null {
        const h = this.hash(name);
        if (h === null) return null;
        return this.entries.find((e) => e.nsec3.covers_hash(e.hash, h))?.owner ?? null;
    }

    // hash returns name's NSEC3 hash, or null when it cannot be computed
    // (an unsupported hash algorithm): the zone then proves nothing.
    private hash(name: string): Uint8Array | null {
        const first = this.entries[0].nsec3;
        try {
            return DNSRR_NSEC3.compute_hash(name, first.hash_algorithm, first.iterations, first.salt);
        } catch {
            return null;
        }
    }
}
