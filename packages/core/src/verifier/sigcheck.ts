// Per-RRSIG results in ZoneStep.signatures: SigCheck construction and
// the chain bookkeeping that keeps each zone's checks once.
//
// Ports dnsdata-go `verifier/sigcheck.go`.

import { SigResult } from '../dnssec/sigcheck';
import { Result, SigCheck, ZoneStep } from './result';
import { StepKind, emit, emit_sig } from './events';
import type { Verifier } from './verifier';

const MILLISECONDS_PER_SECOND = 1000;

// rfc3339 formats Unix seconds as Go's time.Time JSON does for a UTC
// time with no fractional second: "2026-01-01T00:00:00Z".
export function rfc3339(unixSeconds: number): string {
    return new Date(unixSeconds * MILLISECONDS_PER_SECOND).toISOString().replace('.000Z', 'Z');
}

// sig_checks turns the per-RRSIG results over (name, *) into SigChecks.
export function sig_checks(name: string, results: readonly SigResult[]): SigCheck[] {
    return results.map((r) => ({
        name,
        rrType: r.rrsig.type_covered,
        keyTag: r.rrsig.key_tag,
        algorithm: r.rrsig.algorithm,
        signer: r.rrsig.signer,
        inception: rfc3339(r.rrsig.inception),
        expiration: rfc3339(r.rrsig.expire),
        result: r.status,
    }));
}

// add_step puts step into result.chain. A step for the same zone added
// by an earlier hop is kept, and only the signature checks it lacks are
// appended to it, so re-walking a zone adds nothing twice. A new step is
// reported as a StepKind.Zone event, each check added as a Sig event.
export function add_step(v: Verifier, result: Result, step: ZoneStep): void {
    const existing = result.chain.find((s) => s.zone === step.zone);
    if (existing !== undefined) {
        add_sigs(v, existing, step.signatures ?? []);
        return;
    }
    const { signatures, ...rest } = step;
    const added: ZoneStep = { ...rest };
    result.chain.push(added);
    emit(v, StepKind.Zone, added.zone, '');
    add_sigs(v, added, signatures ?? []);
}

// add_zone_sigs appends checks to the chain step of zoneName, which the
// walk has already added.
export function add_zone_sigs(v: Verifier, result: Result, zoneName: string, checks: readonly SigCheck[]): void {
    add_step(v, result, { zone: zoneName, signatures: [...checks] });
}

// add_sigs appends to step each check it does not hold yet.
function add_sigs(v: Verifier, step: ZoneStep, checks: readonly SigCheck[]): void {
    for (const c of checks) {
        if (step.signatures?.some((s) => same_check(s, c))) continue;
        if (step.signatures === undefined) step.signatures = [];
        step.signatures.push(c);
        emit_sig(v, step.zone, c);
    }
}

function same_check(a: SigCheck, b: SigCheck): boolean {
    return a.name === b.name && a.rrType === b.rrType && a.keyTag === b.keyTag &&
        a.algorithm === b.algorithm && a.signer === b.signer && a.result === b.result &&
        a.inception === b.inception && a.expiration === b.expiration;
}
