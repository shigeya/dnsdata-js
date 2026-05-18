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

import { DNSKey, DNSRR_DS } from '../dnssec/dnssec_rr';
import { RRTypeToString } from '../types/dns_type_table';
import { BUILTIN_ROOT_ANCHORS, RootAnchors } from '../dnssec/root_anchors';
import { Resolver } from './resolver';
import { Result } from './result';
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
    // inception / expire windows. v0.1.0's underlying verify_rrsig
    // does not yet consult the clock; this option is accepted for
    // API parity with dnsdata-go and reserved for the expiry-check
    // pass that lands with UP-006 (wildcard) / SHOULD #13.
    now?: () => Date;
}

export class Verifier {
    readonly resolver: Resolver;
    readonly anchors: RootAnchors;
    // Reserved; consulted once verify_rrsig grows a validity-window
    // check (currently unused — kept for API parity with the Go side).
    readonly now: () => Date;

    constructor(opts: VerifierOptions) {
        if (!opts || !opts.resolver) {
            throw new VerifierConfigError('verifier: resolver is required');
        }
        this.resolver = opts.resolver;
        this.anchors = opts.trustAnchors ?? BUILTIN_ROOT_ANCHORS;
        this.now = opts.now ?? (() => new Date());
        // Force handler registration. dnssec_rr.ts performs this at
        // import time; the explicit reference here documents the
        // dependency and matches the Go side's `NewVerifier` →
        // `RegisterHandlers()` call (the registry is idempotent).
        void DNSKey; void DNSRR_DS;
    }

    // Walks the DNSSEC chain of trust from the root zone down to
    // (qname, qtype). See chain.ts::validate for the full contract.
    async validate(qname: string, qtype: number, signal?: AbortSignal): Promise<Result> {
        return validate(this, qname, qtype, signal);
    }
}

//////////////////////////////////////////////////// Shared helpers

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
