// In-memory authoritative server for a set of (signed) zones, usable as
// a verifier Resolver. Ports dnsdata-go `resolver/memory/memory.go`
// (UP-014).
//
// It answers the queries a validating resolver makes (answers with
// their RRSIGs, DNSKEY at each apex, DS from the parent side of a zone
// cut, referrals for delegations it does not hold, NODATA and NXDOMAIN
// with their NSEC or NSEC3 proofs (RFC 5155 §7.2, opt-out included),
// CNAME, DNAME and wildcard synthesis) without any network. Together with the zone signer it lets a whole hierarchy,
// including a private root, be built and validated in a test: the
// verifier's `trustAnchors` option takes the root's anchors from
// `signer.root_anchors`, and its `now` option pins the time.
//
// An [Authority] is immutable after [new_authority]; every response
// carries fresh copies of the records.

import { Resolver } from '../../verifier/resolver';
import { Zone } from '../../zone/dns_zone';
import { ResolverResponse } from '../response';
import { RCODE_REFUSED, answer } from './answer';
import { MemoryConfigError } from './errors';
import { is_at_or_below, labels, normalize } from './names';
import { TYPE_DS, ZoneIndex } from './zone_index';

const MAX_QTYPE = 0xffff;
const MAX_RCODE = 0xff;

// Option configures [new_authority]; build one with [with_zone] or
// [with_fault].
export type Option =
    | { readonly kind: 'zone'; readonly apex: string; readonly zone: Zone }
    | { readonly kind: 'fault'; readonly name: string; readonly qtype: number; readonly rcode: number };

// with_zone serves z as the zone at apex. Every record of z must be at
// or below apex. The zone is indexed once by new_authority; later
// changes to z are not seen.
export function with_zone(apex: string, z: Zone): Option {
    return { kind: 'zone', apex, zone: z };
}

// with_fault makes the authority answer (name, qtype) with rcode and no
// records, for negative tests (for example SERVFAIL = 2).
export function with_fault(name: string, qtype: number, rcode: number): Option {
    return { kind: 'fault', name, qtype, rcode };
}

function fault_key(name: string, qtype: number): string {
    return `${name}\0${qtype}`;
}

function is_uint(n: unknown, max: number): boolean {
    return Number.isInteger(n) && (n as number) >= 0 && (n as number) <= max;
}

// new_authority builds an Authority (Go `New`). At least one zone is
// required; apexes must be fully qualified and distinct. Throws
// MemoryConfigError otherwise, or when a record lies outside its zone.
export function new_authority(...opts: Option[]): Authority {
    const zones: ZoneIndex[] = [];
    const faults = new Map<string, number>();
    for (const opt of opts) {
        if (opt.kind === 'fault') {
            if (!is_uint(opt.qtype, MAX_QTYPE) || !is_uint(opt.rcode, MAX_RCODE)) {
                throw new MemoryConfigError(`fault ${opt.name}: qtype ${opt.qtype} or rcode ${opt.rcode} out of range`);
            }
            faults.set(fault_key(normalize(opt.name), opt.qtype), opt.rcode);
            continue;
        }
        if (!(opt.zone instanceof Zone) || typeof opt.apex !== 'string' || !opt.apex.endsWith('.')) {
            throw new MemoryConfigError(`zone "${opt.apex}" needs a fully qualified apex and a zone`);
        }
        const apex = normalize(opt.apex);
        if (zones.some((z) => z.apex === apex)) {
            throw new MemoryConfigError(`zone ${apex} given twice`);
        }
        zones.push(ZoneIndex.of(apex, opt.zone));
    }
    if (zones.length === 0) {
        throw new MemoryConfigError('no zones');
    }
    return new Authority(zones, faults);
}

// Authority answers queries from the zones it was built with. Create it
// with [new_authority].
export class Authority implements Resolver {
    /** @internal Use [new_authority]. */
    constructor(private readonly zones: readonly ZoneIndex[],
                private readonly faults: ReadonlyMap<string, number>) {}

    // query implements the verifier's Resolver. The name is matched
    // case-insensitively; a trailing dot is optional. A name outside
    // every zone is answered with REFUSED. An aborted signal rejects with
    // its reason.
    async query(name: string, qtype: number, signal?: AbortSignal): Promise<ResolverResponse> {
        signal?.throwIfAborted();
        const qname = normalize(name);
        const rcode = this.faults.get(fault_key(qname, qtype));
        if (rcode !== undefined) {
            return { records: [], ad: false, rcode };
        }
        const idx = this.zone_for(qname, qtype);
        if (idx === null) {
            return { records: [], ad: false, rcode: RCODE_REFUSED };
        }
        return answer(idx, qname, qtype);
    }

    // zone_for picks the deepest zone containing name. A DS query for a
    // zone's apex is answered from the parent side of the cut instead.
    private zone_for(name: string, qtype: number): ZoneIndex | null {
        let best: ZoneIndex | null = null;
        for (const idx of this.zones) {
            if (!is_at_or_below(name, idx.apex)) continue;
            if (qtype === TYPE_DS && name === idx.apex && name !== '.') continue;
            if (best === null || labels(idx.apex).length > labels(best.apex).length) best = idx;
        }
        return best;
    }
}
