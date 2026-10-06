// Step events: the steps of a validate() call, streamed to
// VerifierOptions.onStep (DESIGN.md §4 SHOULD 14).
//
// Ports dnsdata-go `verifier/events.go`.

import { SigStatus } from '../dnssec/sigcheck';
import { AliasStep, Result, SigCheck } from './result';
import { Verdict } from './verdict';
import { type Verifier, qtype_mnemonic } from './verifier';

// StepKind: the kinds of StepEvent, in the order a walk produces them.
export enum StepKind {
    // A query is sent to the resolver. zone is the queried name, detail
    // its type mnemonic.
    Query = 'query',
    // The Cache answered instead. zone and detail as for Query.
    CacheHit = 'cache-hit',
    // The DS rrset of the descent into zone was checked. detail is
    // "verified" or the failure's reason code (as in Result.reasonCode;
    // "error" when the check could not be made).
    DS = 'ds',
    // The DNSKEY rrset of zone was checked. detail as for DS.
    DNSKEY = 'dnskey',
    // A step for zone was added to Result.chain. Each zone is reported
    // once, root first.
    Zone = 'zone',
    // A SigCheck was added to the chain step of zone. sig is a copy of
    // it; the sig events of a validate() call correspond one to one to
    // the SigChecks of its Result.chain.
    Sig = 'sig',
    // A CNAME or DNAME was followed. zone is the zone that signed it,
    // detail "<type> <from> -> <target>".
    Alias = 'alias',
    // The verdict is Insecure. zone is insecureAt, detail
    // "<reason code>: <reason>".
    Insecure = 'insecure',
    // The verdict is Bogus. zone is bogusAt, detail as for Insecure.
    Bogus = 'bogus',
    // The last event of a validate() call that does not reject. zone is
    // the final query name (after aliases), detail the verdict.
    Answer = 'answer',
}

// StepEvent is one step of a validate() call. What zone and detail hold
// depends on kind (see StepKind); detail is '' for Zone and Sig. sig is
// set only on StepKind.Sig.
export interface StepEvent {
    kind: StepKind;
    zone: string;
    sig?: SigCheck;
    detail: string;
}

// emit hands an event to the step handler, if any.
export function emit(v: Verifier, kind: StepKind, zone: string, detail: string): void {
    v.onStep?.({ kind, zone, detail });
}

// emit_lookup reports a query or cache hit for (name, qtype).
export function emit_lookup(v: Verifier, kind: StepKind.Query | StepKind.CacheHit, name: string, qtype: number): void {
    if (v.onStep === undefined) return;
    emit(v, kind, name, qtype_mnemonic(qtype));
}

// emit_sig reports a SigCheck added to the step of zone.
export function emit_sig(v: Verifier, zone: string, sig: SigCheck): void {
    v.onStep?.({ kind: StepKind.Sig, zone, sig: { ...sig }, detail: '' });
}

// emit_rrset_check reports the outcome of a DS or DNSKEY rrset check:
// "verified", the failure's reason code, or "error".
export function emit_rrset_check(v: Verifier, name: string, kind: StepKind.DS | StepKind.DNSKEY | null,
                                 check: { ok: boolean; code?: string }, failed: boolean): void {
    if (v.onStep === undefined || kind === null) return;
    let detail: string = SigStatus.Verified;
    if (!check.ok && check.code) detail = check.code;
    else if (failed) detail = 'error';
    emit(v, kind, name, detail);
}

// emit_alias reports an alias hop.
export function emit_alias(v: Verifier, a: AliasStep): void {
    if (v.onStep === undefined) return;
    emit(v, StepKind.Alias, a.zone, `${a.type} ${a.from} -> ${a.target}`);
}

// emit_verdict reports the classification of result, ending with
// StepKind.Answer.
export function emit_verdict(v: Verifier, result: Result, qname: string): void {
    if (v.onStep === undefined) return;
    if (result.verdict === Verdict.Bogus) {
        emit(v, StepKind.Bogus, result.bogusAt ?? '', `${result.reasonCode ?? ''}: ${result.bogusReason ?? ''}`);
    } else if (result.verdict === Verdict.Insecure) {
        emit(v, StepKind.Insecure, result.insecureAt ?? '', `${result.reasonCode ?? ''}: ${result.insecureReason ?? ''}`);
    }
    emit(v, StepKind.Answer, qname, result.verdict);
}
