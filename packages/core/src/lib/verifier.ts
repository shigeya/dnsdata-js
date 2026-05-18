// DNSSEC chain-of-trust validator with pluggable Resolver
//
// Ported from dnsdata-go `verifier/` package (Go → TS feedback channel,
// tracked as UPSTREAM_FEEDBACK.md UP-001 in the Go repo and
// shigeya/dnsdata-js#5 here).
//
// Scope (v0.1.0): positive validation only — every zone on the path
// from the root down to qname has a usable DNSKEY rrset and the
// qname's rrset is signed by that zone's keys. Negative proofs
// (NSEC / NSEC3 NODATA / NXDOMAIN, Insecure-vs-Bogus distinction at
// a no-DS delegation), CNAME / DNAME chasing, and wildcard
// synthesis are tracked separately (#8, #9, #10).
//
// A note on the descent loop: when the parent zone returns *no* DS
// for a candidate child name we MUST continue walking deeper
// descendants against the same currentZone, NOT bail out to leaf
// resolution. Bailing out leaf-resolves qname under a shallower
// zone's keys whenever an empty non-terminal sits between two real
// cuts (e.g. "ad.jp." between "jp." and "wide.ad.jp."). That class
// of name covers a meaningful slice of `.jp` / `.uk` mail-security
// records, so getting the loop right matters.

import * as crypto from 'crypto';
import { ResourceRecord } from './dns_zone';
import { DNSSecZone, KeyVerifyMode } from './dnssec_zone';
import { DNSKey, DNSRR_DS } from './dnssec_rr';
import { StringToRRType, RRTypeToString } from './dns_type_table';
import {
    BUILTIN_ROOT_ANCHORS,
    RootAnchors,
} from './root_anchors';

const TYPE_DNSKEY = StringToRRType('DNSKEY');
const TYPE_DS = StringToRRType('DS');
const TYPE_RRSIG = StringToRRType('RRSIG');

//////////////////////////////////////////////////////////// Verdict

// The four-state classification from RFC 4033 §5. The cross-language
// JSON schema agreed with dnsdata-go uses these exact lower-case
// strings so callers can switch on the value without conversion.
export enum Verdict {
    Indeterminate = 'indeterminate',
    Secure        = 'secure',
    Insecure      = 'insecure',
    Bogus         = 'bogus',
}

//////////////////////////////////////////////////////////// Resolver

// Transport-shaped dependency the chain walker uses to fetch DNSSEC
// data. Implementations are not required to validate signatures
// themselves — the Verifier does that.
//
// Contract:
//   - name is the fully-qualified, lower-cased, trailing-dot form
//     (the Verifier normalises before calling).
//   - The returned array MUST include every record from the answer
//     section, including any RRSIG records covering the answer rrset.
//     The Verifier filters by type.
//   - An empty array with no thrown error means "name exists, rrset
//     empty" (NODATA). v0.1.0 treats NODATA / NXDOMAIN the same way.
//   - Network / parse / transport problems should be raised as
//     exceptions so Validate can convert them into [Verdict.Indeterminate]
//     wrapped in [VerifierResolverError].
//   - signal MAY be honoured for cancellation; if the resolver
//     observes an aborted signal it should throw — the Verifier
//     re-wraps it as [VerifierChainTimeoutError].
export interface Resolver {
    query(name: string, qtype: number, signal?: AbortSignal): Promise<ResourceRecord[]>;
}

//////////////////////////////////////////////////////////// Errors

// All verifier-thrown errors inherit from VerifierError so callers
// can route them through one `instanceof` check at the outer
// boundary while still discriminating by subclass when they care.

export class VerifierError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'VerifierError';
    }
}

export class VerifierConfigError extends VerifierError {
    constructor(message: string) {
        super(message);
        this.name = 'VerifierConfigError';
    }
}

export class VerifierInvalidQNameError extends VerifierError {
    constructor(message: string) {
        super(message);
        this.name = 'VerifierInvalidQNameError';
    }
}

export class VerifierResolverError extends VerifierError {
    public readonly cause: unknown;
    constructor(message: string, cause: unknown) {
        super(message);
        this.name = 'VerifierResolverError';
        this.cause = cause;
    }
}

export class VerifierChainTimeoutError extends VerifierError {
    public readonly cause: unknown;
    constructor(message: string, cause?: unknown) {
        super(message);
        this.name = 'VerifierChainTimeoutError';
        this.cause = cause;
    }
}

export class VerifierTrustAnchorMismatchError extends VerifierError {
    constructor(message: string) {
        super(message);
        this.name = 'VerifierTrustAnchorMismatchError';
    }
}

//////////////////////////////////////////////////////////// Result types

export interface KeySummary {
    keyTag: number;
    algorithm: number;
    sep: boolean;
}

export interface DSSummary {
    keyTag: number;
    algorithm: number;
    digestType: number;
}

export interface ZoneStep {
    zone: string;
    dnskeys?: KeySummary[];
    dsDigests?: DSSummary[];
    signedBy?: KeySummary;
}

// Presentation-form RR values keyed by zone / owner so consumers
// (mailsec-probe Signals, audit views) can render the evidence
// without re-querying. Mirrors dnsdata-go `verifier.Evidence`.
export interface Evidence {
    dnskeys: Record<string, string[]>;
    dses:    Record<string, string[]>;
    // Composite key "<name>/<rrtype>" so signatures stay separable
    // per rrset.
    rrsigs:  Record<string, string[]>;
}

export interface Result {
    verdict: Verdict;
    chain: ZoneStep[];
    insecureAt?: string;
    insecureReason?: string;
    bogusAt?: string;
    bogusReason?: string;
    evidence: Evidence;
}

//////////////////////////////////////////////////////////// Verifier

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
    private readonly resolver: Resolver;
    private readonly anchors: RootAnchors;
    // Reserved; consulted once verify_rrsig grows a validity-window
    // check (currently unused — kept for API parity with the Go side).
    private readonly _now: () => Date;

    constructor(opts: VerifierOptions) {
        if (!opts || !opts.resolver) {
            throw new VerifierConfigError('verifier: resolver is required');
        }
        this.resolver = opts.resolver;
        this.anchors = opts.trustAnchors ?? BUILTIN_ROOT_ANCHORS;
        this._now = opts.now ?? (() => new Date());
        // Force handler registration. dnssec_rr.ts performs this at
        // import time; the explicit reference here documents the
        // dependency and matches the Go side's `NewVerifier` →
        // `RegisterHandlers()` call (the registry is idempotent).
        void DNSKey; void DNSRR_DS;
    }

    // Walks the DNSSEC chain of trust from the root zone down to
    // (qname, qtype), classifies the outcome, and returns the
    // evidence gathered along the way.
    //
    // Returns Result.verdict = Bogus for verified-but-broken chains;
    // throws (VerifierError or subclass) when the chain could not be
    // walked at all (resolver failure, abort, invalid qname).
    async validate(qname: string, qtype: number, signal?: AbortSignal): Promise<Result> {
        if (!qname) {
            throw new VerifierInvalidQNameError('verifier: qname is empty');
        }
        const result: Result = {
            verdict: Verdict.Indeterminate,
            chain: [],
            evidence: { dnskeys: {}, dses: {}, rrsigs: {} },
        };
        const normalizedQName = normalize_qname(qname);

        // Step 1: load + verify the root zone.
        const rootZone = new DNSSecZone();
        await this.load_records(rootZone, '.', TYPE_DNSKEY, result, signal);

        const rootKSK = this.match_ksk_with_anchors(rootZone);
        if (!rootKSK) {
            result.verdict = Verdict.Bogus;
            result.bogusAt = '.';
            result.bogusReason = 'root KSK does not match any configured trust anchor';
            return result;
        }
        rootZone.add_sep('.');
        const rootDnskeyOK = rootZone.verify_rrset('.', TYPE_DNSKEY, KeyVerifyMode.KSK);
        if (!rootDnskeyOK) {
            result.verdict = Verdict.Bogus;
            result.bogusAt = '.';
            result.bogusReason = 'root DNSKEY rrset signature did not verify';
            return result;
        }
        result.chain.push(summarize_zone('.', rootZone, rootKSK));

        // Step 2: descend through each label boundary that's actually
        // a zone cut. Empty non-terminals (no DS, but a deeper name
        // *is* a cut) MUST be skipped, not treated as the leaf — see
        // the file header comment.
        let currentZone = rootZone;
        let currentName = '.';
        for (const childName of descendant_zones(normalizedQName)) {
            check_aborted(signal);

            const dsCount = await this.load_records(currentZone, childName, TYPE_DS, result, signal);
            if (dsCount === 0) {
                // childName is not a zone cut under currentZone — most
                // often that's qname itself, but it can also be an
                // empty non-terminal between two real cuts (e.g.
                // "ad.jp." between "jp." and "wide.ad.jp."). Continue
                // so the loop tries deeper descendants against the
                // same currentZone; descent finalises only when (a)
                // descendant_zones is exhausted or (b) a real cut is
                // found and verified.
                continue;
            }

            const dsOK = currentZone.verify_rrset(childName, TYPE_DS);
            if (!dsOK) {
                result.verdict = Verdict.Bogus;
                result.bogusAt = childName;
                result.bogusReason = `DS rrset for ${childName} did not verify under ${currentName}`;
                return result;
            }

            // Load child DNSKEY rrset into a fresh zone parented at
            // currentZone, so verify_delegation_signer can reach the
            // parent's DS records.
            const childZone = new DNSSecZone();
            childZone.parent = currentZone;
            await this.load_records(childZone, childName, TYPE_DNSKEY, result, signal);

            const childKSK = match_ksk_with_ds(childZone, currentZone, childName);
            if (!childKSK) {
                result.verdict = Verdict.Bogus;
                result.bogusAt = childName;
                result.bogusReason = `no DNSKEY at ${childName} matched a DS record in ${currentName}`;
                return result;
            }
            childZone.add_sep(childName);
            const childDnskeyOK = childZone.verify_rrset(childName, TYPE_DNSKEY, KeyVerifyMode.KSK);
            if (!childDnskeyOK) {
                result.verdict = Verdict.Bogus;
                result.bogusAt = childName;
                result.bogusReason = `DNSKEY rrset for ${childName} did not verify under its own KSK`;
                return result;
            }

            result.chain.push(summarize_zone(childName, childZone, childKSK));
            currentZone = childZone;
            currentName = childName;
        }

        // Step 3: leaf resolution against the deepest cut we descended
        // into. qtype lookup happens here so the chain-walk only deals
        // in DNSKEY / DS / RRSIG.
        check_aborted(signal);
        const leafCount = await this.load_records(currentZone, normalizedQName, qtype, result, signal);
        if (leafCount === 0) {
            // v0.1.0 cannot tell NODATA / NXDOMAIN from "resolver
            // returned nothing" — NSEC / NSEC3 negative proofs land
            // with UP-004 (#8). Until then, surface as Indeterminate.
            return result;
        }
        const leafOK = currentZone.verify_rrset(normalizedQName, qtype);
        if (!leafOK) {
            result.verdict = Verdict.Bogus;
            result.bogusAt = currentName;
            result.bogusReason = `RRSIG over ${normalizedQName}/${qtype_mnemonic(qtype)} did not verify under ${currentName}`;
            return result;
        }
        result.verdict = Verdict.Secure;
        return result;
    }

    // Issues one resolver Query and appends every returned record to
    // z, capturing presentation values into result.evidence. Returns
    // the number of records matching qtype (so the caller can detect
    // a missing rrset).
    private async load_records(
        z: DNSSecZone,
        name: string,
        qtype: number,
        result: Result,
        signal?: AbortSignal,
    ): Promise<number> {
        check_aborted(signal);
        let records: ResourceRecord[];
        try {
            records = await this.resolver.query(name, qtype, signal);
        } catch (err: unknown) {
            if (is_abort_error(err) || signal?.aborted) {
                throw new VerifierChainTimeoutError(
                    `verifier: chain walk aborted while querying ${name}/${qtype_mnemonic(qtype)}`,
                    err,
                );
            }
            throw new VerifierResolverError(
                `verifier: resolver failed for ${name}/${qtype_mnemonic(qtype)}: ${error_message(err)}`,
                err,
            );
        }

        let matching = 0;
        for (const rr of records) {
            z.add_rr(rr);
            if (rr.type === TYPE_DNSKEY) {
                push_evidence(result.evidence.dnskeys, rr.label, rr.value);
            } else if (rr.type === TYPE_DS) {
                push_evidence(result.evidence.dses, rr.label, rr.value);
            } else if (rr.type === TYPE_RRSIG) {
                const key = `${rr.label}/${qtype_mnemonic(qtype)}`;
                push_evidence(result.evidence.rrsigs, key, rr.value);
            }
            if (rr.type === qtype) matching++;
        }
        return matching;
    }

    // Returns the first SEP-flagged DNSKEY in the root zone whose
    // DS digest matches one of the configured trust anchors.
    private match_ksk_with_anchors(rootZone: DNSSecZone): DNSKey | null {
        if (!this.anchors.ds || this.anchors.ds.length === 0) {
            return null;
        }
        const dnskeys = rootZone.find_rrset('.', TYPE_DNSKEY);
        for (const rr of dnskeys) {
            const handler = rr.get_handler();
            if (!(handler instanceof DNSKey) || !handler.is_secure_entry_point()) continue;
            for (const anchor of this.anchors.ds) {
                if (anchor.keyTag !== handler.key_tag || anchor.algorithm !== handler.algorithm) {
                    continue;
                }
                if (verify_anchor_digest(handler, anchor)) {
                    return handler;
                }
            }
        }
        return null;
    }
}

//////////////////////////////////////////////////////////// Helpers

// Returns the proper-suffix zone names of qname from shallowest to
// deepest, excluding the root and INCLUDING qname itself. The
// inclusion of qname lets the descent loop notice a "qname is not a
// cut" case (no DS at qname → leaf resolution).
//
//   "www.example.com." → ["com.", "example.com.", "www.example.com."]
//
// Exported for tests.
export function descendant_zones(qname: string): string[] {
    qname = normalize_qname(qname);
    if (qname === '.') return [];
    const trimmed = qname.endsWith('.') ? qname.slice(0, -1) : qname;
    const labels = trimmed.split('.');
    const out: string[] = [];
    for (let i = labels.length - 1; i >= 0; i--) {
        out.push(labels.slice(i).join('.') + '.');
    }
    return out;
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
function qtype_mnemonic(t: number): string {
    try {
        return RRTypeToString(t);
    } catch {
        return `TYPE${t}`;
    }
}

function push_evidence(into: Record<string, string[]>, key: string, value: string): void {
    const list = into[key];
    if (list) list.push(value);
    else into[key] = [value];
}

function summarize_zone(zoneName: string, z: DNSSecZone, ksk: DNSKey): ZoneStep {
    const step: ZoneStep = { zone: zoneName };

    const dnskeyRRs = z.find_rrset(zoneName, TYPE_DNSKEY);
    if (dnskeyRRs.length > 0) {
        step.dnskeys = [];
        for (const rr of dnskeyRRs) {
            const h = rr.get_handler();
            if (h instanceof DNSKey) {
                step.dnskeys.push({
                    keyTag: h.key_tag,
                    algorithm: h.algorithm,
                    sep: h.is_secure_entry_point(),
                });
            }
        }
    }

    const dsRRs = z.find_rrset(zoneName, TYPE_DS);
    if (dsRRs.length > 0) {
        step.dsDigests = [];
        for (const rr of dsRRs) {
            const h = rr.get_handler();
            if (h instanceof DNSRR_DS) {
                step.dsDigests.push({
                    keyTag: h.key_tag,
                    algorithm: h.algorithm,
                    digestType: h.digest_type,
                });
            }
        }
    }

    step.signedBy = {
        keyTag: ksk.key_tag,
        algorithm: ksk.algorithm,
        sep: ksk.is_secure_entry_point(),
    };
    return step;
}

// Returns the first SEP-flagged DNSKEY in childZone whose DS digest
// matches one of the DS records present at parentZone under childName.
function match_ksk_with_ds(childZone: DNSSecZone, parentZone: DNSSecZone, childName: string): DNSKey | null {
    const dnskeys = childZone.find_rrset(childName, TYPE_DNSKEY);
    const dsRRs = parentZone.find_rrset(childName, TYPE_DS);
    if (dnskeys.length === 0 || dsRRs.length === 0) return null;

    for (const rr of dnskeys) {
        const key = rr.get_handler();
        if (!(key instanceof DNSKey) || !key.is_secure_entry_point()) continue;
        for (const dsRR of dsRRs) {
            const ds = dsRR.get_handler();
            if (!(ds instanceof DNSRR_DS)) continue;
            if (ds.key_tag !== key.key_tag || ds.algorithm !== key.algorithm) continue;
            if (ds.verify_digest(key.get_ds_digest_data())) {
                return key;
            }
        }
    }
    return null;
}

// Computes the DS digest from a candidate DNSKEY and compares it
// against an anchor record drawn from the configured trust-anchor
// set. The crypto algorithm comes from the anchor's digestType,
// matching the existing DS-digest path in dnssec_rr.ts.
function verify_anchor_digest(key: DNSKey, anchor: { digestType: number; digest: string }): boolean {
    const algo = ds_digest_algorithm(anchor.digestType);
    if (!algo) return false;
    const computed = crypto.createHash(algo).update(Buffer.from(key.get_ds_digest_data())).digest();
    const expected = Buffer.from(anchor.digest.replace(/\s+/g, ''), 'hex');
    return computed.equals(expected);
}

function ds_digest_algorithm(digestType: number): string | null {
    switch (digestType) {
        case 1: return 'sha1';
        case 2: return 'sha256';
        case 4: return 'sha384';
        default: return null;
    }
}

function check_aborted(signal?: AbortSignal): void {
    if (signal?.aborted) {
        throw new VerifierChainTimeoutError('verifier: chain walk aborted', signal.reason);
    }
}

function is_abort_error(err: unknown): boolean {
    if (err && typeof err === 'object') {
        const e = err as { name?: string; code?: string };
        if (e.name === 'AbortError') return true;
        if (e.code === 'ABORT_ERR') return true;
    }
    return false;
}

function error_message(err: unknown): string {
    if (err instanceof Error) return err.message;
    return String(err);
}
