// Read-only view of one zone, built once by [new_authority]. Ports
// dnsdata-go `resolver/memory/index.go`.

import { DNSRR_NSEC } from '../../dnssec/nsec';
import { RRSig } from '../../dnssec/rrsig';
import { StringToRRType } from '../../types/dns_type_table';
import { ResourceRecord, Zone } from '../../zone/dns_zone';
import { MemoryConfigError } from './errors';
import { is_at_or_below, labels, normalize, parent } from './names';

export const TYPE_NS = StringToRRType('NS');
export const TYPE_CNAME = StringToRRType('CNAME');
export const TYPE_DNAME = StringToRRType('DNAME');
export const TYPE_DS = StringToRRType('DS');
export const TYPE_RRSIG = StringToRRType('RRSIG');
export const TYPE_NSEC = StringToRRType('NSEC');

// An NSEC record at owner, parsed for range checks.
interface NsecEntry {
    readonly owner: string;
    readonly nsec: DNSRR_NSEC;
}

function error_message(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
}

export class ZoneIndex {
    // owner → records
    private readonly by_name = new Map<string, ResourceRecord[]>();
    // RRSIG → type covered
    private readonly covered = new Map<ResourceRecord, number>();
    // owners and their ancestors down to the apex
    private readonly exists = new Set<string>();
    // delegation points
    private readonly cuts: string[] = [];
    private readonly nsecs: NsecEntry[] = [];

    private constructor(readonly apex: string) {}

    // of indexes the records of z, which must all be at or below apex
    // (normalized). Throws MemoryConfigError otherwise.
    static of(apex: string, z: Zone): ZoneIndex {
        const idx = new ZoneIndex(apex);
        for (const rr of z.all_records()) idx.add(rr);
        return idx;
    }

    private add(rr: ResourceRecord): void {
        const owner = normalize(rr.label);
        if (!is_at_or_below(owner, this.apex)) {
            throw new MemoryConfigError(`${rr.label} is outside the zone ${this.apex}`);
        }
        this.by_name.set(owner, [...(this.by_name.get(owner) ?? []), rr]);
        for (let n = owner; !this.exists.has(n); n = parent(n)) {
            this.exists.add(n);
            if (n === this.apex) break;
        }
        if (rr.type === TYPE_RRSIG) {
            this.covered.set(rr, this.parse(rr, 'RRSIG', (v) => new RRSig(null, v).type_covered));
        } else if (rr.type === TYPE_NSEC) {
            this.nsecs.push({ owner, nsec: this.parse(rr, 'NSEC', (v) => new DNSRR_NSEC(null, v)) });
        } else if (rr.type === TYPE_NS && owner !== this.apex && !this.cuts.includes(owner)) {
            this.cuts.push(owner);
        }
    }

    private parse<T>(rr: ResourceRecord, what: string, parse: (value: string) => T): T {
        try {
            return parse(rr.value);
        } catch (e) {
            throw new MemoryConfigError(`${what} at ${rr.label}: ${error_message(e)}`);
        }
    }

    // records returns every record owned by name.
    records(name: string): readonly ResourceRecord[] {
        return this.by_name.get(name) ?? [];
    }

    // has_name reports whether name is an owner or an empty non-terminal.
    has_name(name: string): boolean {
        return this.exists.has(name);
    }

    // rrset returns the records of type t at name.
    rrset(name: string, t: number): ResourceRecord[] {
        return this.records(name).filter((rr) => rr.type === t);
    }

    // with_sigs returns the (name, t) RRset followed by the RRSIGs
    // covering it; empty when there is no such RRset.
    with_sigs(name: string, t: number): ResourceRecord[] {
        const out = this.rrset(name, t);
        if (out.length === 0) return [];
        const sigs = this.rrset(name, TYPE_RRSIG).filter((rr) => this.covered.get(rr) === t);
        return [...out, ...sigs];
    }

    // cut_above returns the delegation point closest to the apex at or
    // above name, or null.
    cut_above(name: string): string | null {
        let best: string | null = null;
        for (const c of this.cuts) {
            if (is_at_or_below(name, c) && (best === null || labels(c).length < labels(best).length)) {
                best = c;
            }
        }
        return best;
    }

    // closest_encloser returns the deepest existing ancestor of name.
    closest_encloser(name: string): string {
        let n = name;
        while (!this.exists.has(n) && n !== this.apex && n !== '.') n = parent(n);
        return n;
    }

    // covering_nsec returns the NSEC (with signatures) whose range covers
    // target, or an empty list.
    covering_nsec(target: string): ResourceRecord[] {
        const e = this.nsecs.find((entry) => entry.nsec.covers_name(entry.owner, target));
        return e === undefined ? [] : this.with_sigs(e.owner, TYPE_NSEC);
    }

    // dname_above returns the owner of a DNAME strictly above name within
    // the zone, or null.
    dname_above(name: string): string | null {
        for (let n = parent(name); is_at_or_below(n, this.apex); n = parent(n)) {
            if (this.rrset(n, TYPE_DNAME).length > 0) return n;
            if (n === this.apex) break;
        }
        return null;
    }
}
