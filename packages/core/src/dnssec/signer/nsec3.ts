// NSEC3 chain construction of the zone signer. Ports dnsdata-go
// `dnssec/signer/nsec3.go`.

import { DNSRR_NSEC3 } from '../nsec3';
import { base32hex_encode } from '../../wire/rdata_decoder';
import { ResourceRecord, Zone } from '../../zone/dns_zone';
import { SignerError, error_message } from './errors';
import { is_at_or_below, labels_of, same_name } from './names';
import {
    TYPE_NSEC3,
    TYPE_NSEC3PARAM,
    TYPE_RRSIG,
    ZoneView,
    chain_ttl,
    register_handlers,
    type_names,
} from './nsec';

// NSEC3Options selects an NSEC3 chain (RFC 5155) in place of NSEC. The
// empty object is the RFC 9276 §3.1 recommendation: no additional
// iterations, no salt, no opt-out.
export interface NSEC3Options {
    iterations?: number;
    salt?: Uint8Array;
    // optOut leaves unsigned delegations out of the chain and sets the
    // opt-out flag on every NSEC3 (RFC 5155 §6).
    optOut?: boolean;
}

const NSEC3_HASH_SHA1 = 1;      // RFC 5155 §11, the only defined algorithm
const NSEC3_FLAG_OPT_OUT = 0x01; // RFC 5155 §3.1.2.1
const MAX_NSEC3_SALT_LENGTH = 255;
const MAX_NSEC3_ITERATIONS = 0xffff;

// One name of the chain: its hash and its bitmap text.
interface NSEC3Link {
    hash: Uint8Array;
    bitmap: string;
}

// build_nsec3 returns the NSEC3 chain for the zone at apex (RFC 5155
// §7.1) followed by the NSEC3PARAM for the apex. Each authoritative
// owner name and each empty non-terminal above one gets an NSEC3, owned
// by the base32hex hash of the name under apex and linked in hash
// order, the last back to the first. The bitmap lists the types at the
// name (at a delegation point only NS and DS), RRSIG where the name has
// a signed RRset, and NSEC3PARAM at the apex; an empty non-terminal's
// is empty. With params.optOut, delegations without DS (and empty
// non-terminals only above them) are left out. Names below a
// delegation (glue) get none, and existing RRSIG / NSEC / NSEC3 /
// NSEC3PARAM records in z are ignored.
//
// ttl 0 (the default) uses min(SOA TTL, SOA MINIMUM) (RFC 9077), or
// 3600 without an SOA at the apex; the NSEC3PARAM gets the same TTL.
// Like sign_zone, it registers the bundled handlers. Throws SignerError.
export function build_nsec3(z: Zone, apex: string, ttl = 0, params: NSEC3Options = {}): ResourceRecord[] {
    register_handlers();
    const iterations = params.iterations ?? 0;
    const salt = params.salt ?? new Uint8Array(0);
    check_params(iterations, salt);
    const view = ZoneView.of(z, apex);
    const nsec3_ttl = chain_ttl(z, apex, ttl);
    const links = hash_names(nsec3_names(view, apex, params.optOut === true), iterations, salt);
    const salt_text = salt.length > 0 ? Buffer.from(salt).toString('hex').toUpperCase() : '-';
    const flags = params.optOut === true ? NSEC3_FLAG_OPT_OUT : 0;
    const out = links.map((l, i) => {
        const next = base32hex_encode(links[(i + 1) % links.length].hash);
        const value = `${NSEC3_HASH_SHA1} ${flags} ${iterations} ${salt_text} ${next} ${l.bitmap}`.trim();
        return new ResourceRecord(nsec3_owner(l.hash, apex), nsec3_ttl, 'IN', TYPE_NSEC3, value);
    });
    out.push(new ResourceRecord(apex, nsec3_ttl, 'IN', TYPE_NSEC3PARAM,
        `${NSEC3_HASH_SHA1} 0 ${iterations} ${salt_text}`));
    return out;
}

function check_params(iterations: number, salt: Uint8Array): void {
    if (!Number.isInteger(iterations) || iterations < 0 || iterations > MAX_NSEC3_ITERATIONS) {
        throw new SignerError(`NSEC3 iterations ${iterations}`);
    }
    if (salt.length > MAX_NSEC3_SALT_LENGTH) {
        throw new SignerError(`NSEC3 salt of ${salt.length} octets`);
    }
}

// hash_names hashes every name and returns the links in hash order.
function hash_names(names: ReadonlyMap<string, string>, iterations: number, salt: Uint8Array): NSEC3Link[] {
    const links = [...names].map(([name, bitmap]) => {
        try {
            return { hash: DNSRR_NSEC3.compute_hash(name, NSEC3_HASH_SHA1, iterations, salt), bitmap };
        } catch (e) {
            throw new SignerError(`NSEC3 hash of ${name}: ${error_message(e)}`);
        }
    });
    links.sort((a, b) => Buffer.compare(a.hash, b.hash));
    for (let i = 1; i < links.length; i++) {
        if (Buffer.compare(links[i - 1].hash, links[i].hash) === 0) {
            throw new SignerError('NSEC3 hash collision; use another salt');
        }
    }
    return links;
}

function nsec3_owner(hash: Uint8Array, apex: string): string {
    const label = base32hex_encode(hash);
    return apex === '.' ? `${label}.` : `${label}.${apex}`;
}

// nsec3_names returns the lower-cased names that get an NSEC3, each with
// its bitmap text.
function nsec3_names(view: ZoneView, apex: string, opt_out: boolean): Map<string, string> {
    const names = new Map<string, string>();
    for (const owner of view.owners) {
        if (view.is_occluded(owner) || (opt_out && !view.is_signed(owner))) continue;
        names.set(owner.toLowerCase(), nsec3_bitmap_text(view, owner, apex));
        for (let n = parent_name(owner); !same_name(n, apex) && is_at_or_below(n, apex); n = parent_name(n)) {
            if (view.types_at(n).length === 0) names.set(n, '');
        }
    }
    return names;
}

// nsec3_bitmap_text lists the types for owner's NSEC3 in presentation form.
function nsec3_bitmap_text(view: ZoneView, owner: string, apex: string): string {
    const present = view.chain_types(owner);
    if (view.is_signed(owner)) present.push(TYPE_RRSIG);
    if (same_name(owner, apex)) present.push(TYPE_NSEC3PARAM);
    return type_names(present);
}

// parent_name returns name one label shorter, lower-cased; the root is
// its own parent.
function parent_name(name: string): string {
    const labels = labels_of(name);
    return labels.length <= 1 ? '.' : `${labels.slice(1).join('.')}.`;
}
