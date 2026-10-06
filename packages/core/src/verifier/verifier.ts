// DNSSEC chain-of-trust validator with pluggable Resolver.
//
// This file is the package shell: it owns the [Verifier] class
// declaration, its constructor, and the small AbortSignal-related
// helpers that the rest of the package shares.  All real work lives
// in the sibling files of the verifier/ package:
//
//   - chain.ts          chain walk (validate / validate_one_hop / leaf)
//   - alias.ts          CNAME / DNAME hop construction
//   - negative.ts       no-DS proofs + NSEC candidate collection
//   - leaf_negative.ts  NODATA / NXDOMAIN proofs + name helpers
//   - wildcard.ts       RFC 4035 §5.3.4 wildcard non-existence proof
//   - verdict.ts        Verdict enum + worst-of combinator
//   - answer.ts         the validated RRset carried on Result.answer
//   - result.ts         Result + HopOutcome + summary structs
//   - resolver.ts       Resolver dependency interface
//   - errors.ts         VerifierError hierarchy
//
// Layout mirrors dnsdata-go `verifier/`; the per-file mapping is
// 1:1 with the same-named .go files.  Per REFACTOR_PLAN.md §3 note,
// AbortSignal handling (`check_aborted`, `is_abort_error`) is kept
// in this shell because the TS Promise/AbortSignal model splits
// responsibility differently from Go's context.Context — keeping
// these helpers in the shell avoids spreading the abort wiring
// across the per-hop files.

import { RRTypeToString } from '../types/dns_type_table';
import { BUILTIN_ROOT_ANCHORS, RootAnchors } from '../dnssec/root_anchors';
import { register_dnssec_handlers_into } from '../dnssec/handlers';
import { Registry } from '../zone/registry';
import { register_legacy_handlers_into } from '../zone/handlers';
import { Resolver } from './resolver';
import { Result } from './result';
import { Cache } from './cache';
import type { StepEvent } from './events';
import { VerifierConfigError, VerifierChainTimeoutError } from './errors';
// chain.ts depends on this file for the Verifier class type and the
// shared helpers below; this import is value-only because we call
// the validate() entry function from the class delegator.
import { validate } from './chain';

export interface VerifierOptions {
    // Required. Transport-shaped dependency that returns the answer
    // section for a (name, qtype) pair.
    resolver: Resolver;

    // Optional. Override the built-in IANA root anchors — useful for
    // test setups that mint their own root KSK.
    trustAnchors?: RootAnchors;

    // Optional. Source of "now" used when comparing against RRSIG
    // inception / expiration windows (RFC 4035 §5.3.1, both ends
    // inclusive). A signature outside its window does not verify, so
    // the chain is Bogus. Defaults to the system clock.
    now?: () => Date;

    // Optional. Pluggable cache consulted before every Resolver.query
    // call. Sharing one Cache across validate() invocations lets a
    // batch run reuse root and TLD DNSKEY / DS rrsets and is the
    // intended way to satisfy DESIGN.md §4 SHOULD #13. A nullish
    // value is treated as no cache attached.
    cache?: Cache;

    // Optional. The registry the Verifier resolves record handlers
    // through, instead of its own registry of the DNSSEC handlers. Use
    // it to add handlers, e.g. the zone types:
    //
    //   const registry = new Registry();
    //   register_dnssec_handlers_into(registry);
    //   register_legacy_handlers_into(registry);
    //   new Verifier({ resolver, registry });
    //
    // It must hold the DNSSEC handlers for validation to succeed.
    // Passing default_registry() shares the process-wide registry, and
    // with it the handlers ResourceRecord.get_handler() returns. A
    // nullish value is treated as not set. It cannot be combined with
    // zoneHandlers.
    registry?: Registry;

    // Optional. When true, the Verifier's own registry also holds the
    // bundled zone handlers (register_legacy_handlers_into: TLSA,
    // SMIMEA, SVCB, HTTPS, ...), next to the DNSSEC handlers. Use it
    // when the resolver returns records in presentation form without
    // their RDATA octets, e.g. an in-memory authority built from zone
    // text, so that they encode for signature checks. It is the
    // shorthand for the registry example above and, like the default,
    // leaves the default registry untouched. A record that does carry
    // its octets is then encoded by its handler from the presentation
    // form rather than written as received. Ports dnsdata-go
    // `verifier.WithZoneHandlers`.
    zoneHandlers?: boolean;

    // Optional. Receives the steps of every validate() call (StepEvent,
    // DESIGN.md §4 SHOULD 14), e.g. for verbose logging. It is called
    // synchronously from inside validate(), never after the returned
    // promise settles, so a slow handler slows validation; an exception
    // it throws rejects that validate(). Absent (the default), it costs
    // nothing. The library itself never writes to stdout or stderr;
    // routing events there is the caller's choice.
    onStep?: (e: StepEvent) => void;
}

export class Verifier {
    readonly resolver: Resolver;
    readonly anchors: RootAnchors;
    // Clock set on every DNSSecZone the chain walker builds; RRSIG
    // validity windows are checked against it.
    readonly now: () => Date;
    readonly cache?: Cache;
    // Registry set on every DNSSecZone the chain walker builds.
    readonly registry: Registry;
    readonly onStep?: (e: StepEvent) => void;

    // The Verifier resolves record handlers through a Registry it owns:
    // by default a fresh one holding the DNSSEC handlers
    // (register_dnssec_handlers_into), or VerifierOptions.registry. It
    // never touches the default registry, so it works without
    // registerAllHandlers() (DESIGN.md §4 MUST NOT 22). The zone
    // handlers are not in the default set: an answer the resolver
    // clients received (TLSA, SVCB, ...) carries its RDATA octets, which
    // sign as they are (new_resource_record_with_rdata). A resolver that
    // returns such records without their octets needs zoneHandlers.
    //
    // Records are shared with the resolver and any Cache. A handler
    // cached on a record is tied to the registry that built it
    // (ResourceRecord.get_handler), so Verifiers with different
    // registries sharing one cache stay independent.
    constructor(opts: VerifierOptions) {
        if (!opts || !opts.resolver) {
            throw new VerifierConfigError('verifier: resolver is required');
        }
        this.resolver = opts.resolver;
        this.anchors = opts.trustAnchors ?? BUILTIN_ROOT_ANCHORS;
        this.now = opts.now ?? (() => new Date());
        if (opts.cache != null) this.cache = opts.cache;
        if (opts.registry != null && opts.zoneHandlers === true) {
            throw new VerifierConfigError('verifier: registry and zoneHandlers are exclusive');
        }
        this.registry = opts.registry ?? own_registry(opts.zoneHandlers === true);
        if (opts.onStep != null) this.onStep = opts.onStep;
    }

    // Walks the DNSSEC chain of trust from the root zone down to
    // (qname, qtype). See chain.ts::validate for the full contract.
    async validate(qname: string, qtype: number, signal?: AbortSignal): Promise<Result> {
        return validate(this, qname, qtype, signal);
    }
}

//////////////////////////////////////////////////// Shared helpers

// own_registry returns a fresh registry holding the DNSSEC handlers and,
// with zone_handlers, the zone handlers.
function own_registry(zone_handlers: boolean): Registry {
    const registry = new Registry();
    register_dnssec_handlers_into(registry);
    if (zone_handlers) register_legacy_handlers_into(registry);
    return registry;
}

// Lower-cases qname and ensures it ends with a single trailing dot.
// Exported for tests.
export function normalize_qname(s: string): string {
    const trimmed = s.trim().toLowerCase();
    if (trimmed === '') return '.';
    return trimmed.endsWith('.') ? trimmed : trimmed + '.';
}

// Canonical RR-type mnemonic, falling back to "TYPE<n>" for unknown
// codes — matches presentation-form rendering.
export function qtype_mnemonic(t: number): string {
    try {
        return RRTypeToString(t);
    } catch {
        return `TYPE${t}`;
    }
}

export function check_aborted(signal?: AbortSignal): void {
    if (signal?.aborted) {
        throw new VerifierChainTimeoutError('verifier: chain walk aborted', signal.reason);
    }
}

export function is_abort_error(err: unknown): boolean {
    if (err && typeof err === 'object') {
        const e = err as { name?: string; code?: string };
        if (e.name === 'AbortError') return true;
        if (e.code === 'ABORT_ERR') return true;
    }
    return false;
}

export function error_message(err: unknown): string {
    if (err instanceof Error) return err.message;
    return String(err);
}
