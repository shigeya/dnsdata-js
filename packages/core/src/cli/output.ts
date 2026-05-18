// CLI output formatting.
//
// Renders a query result + an optional DNSSEC chain Verifier verdict
// in a dig-like layout. The new CLI (P2 of REFACTOR_PLAN.md) consumes
// ResourceRecord[] from lib/resolver/{doh,auth} directly and a
// six-state lib/verifier.Result rather than the legacy
// VerificationResult.

import { ResourceRecord } from '../zone/dns_zone';
import { RRTypeToString } from '../types/dns_type_table';
import { Result, AliasStep, KeySummary, DSSummary, ZoneStep } from '../verifier';

export interface OutputContext {
    fqdn: string;
    rrtype: string;
    method_desc: string;
    records: readonly ResourceRecord[];
    result?: Result;
    verify_error?: string;
}

function pad_right(s: string, len: number): string {
    return s.length >= len ? s : s + ' '.repeat(len - s.length);
}

function type_name(type: number): string {
    try { return RRTypeToString(type); }
    catch { return String(type); }
}

function format_record(rr: ResourceRecord): string {
    return `${pad_right(rr.label, 24)} ${String(rr.ttl).padStart(6)}  IN  ${pad_right(type_name(rr.type), 8)} ${rr.value}`;
}

function format_key(k: KeySummary): string {
    return `${k.keyTag}/${k.algorithm}${k.sep ? '(KSK)' : ''}`;
}

function format_ds(d: DSSummary): string {
    return `${d.keyTag}/${d.algorithm}/${d.digestType}`;
}

function format_chain_step(step: ZoneStep): string {
    const parts: string[] = [];
    if (step.dnskeys && step.dnskeys.length > 0) {
        parts.push(`DNSKEY=[${step.dnskeys.map(format_key).join(', ')}]`);
    }
    if (step.dsDigests && step.dsDigests.length > 0) {
        parts.push(`DS=[${step.dsDigests.map(format_ds).join(', ')}]`);
    }
    if (step.signedBy) {
        parts.push(`signed-by=${format_key(step.signedBy)}`);
    }
    const zone = step.zone || '.';
    return parts.length > 0 ? `${zone} ${parts.join(', ')}` : zone;
}

function format_alias(a: AliasStep): string {
    return `${a.type.toUpperCase()} ${a.from} -> ${a.target} (zone=${a.zone}, ${a.verdict})`;
}

export function format_output(ctx: OutputContext): string {
    const lines: string[] = [];

    lines.push(`; <<>> dnsdata lookup <<>> ${ctx.fqdn} ${ctx.rrtype}`);
    lines.push(`;; Method: ${ctx.method_desc}`);
    lines.push('');

    if (ctx.records.length > 0) {
        lines.push(';; RECORDS:');
        for (const rr of ctx.records) lines.push(format_record(rr));
        lines.push('');
    } else {
        lines.push(';; No records returned.');
        lines.push('');
    }

    if (ctx.verify_error) {
        lines.push(';; DNSSEC VERIFICATION:');
        lines.push(`;;   Error: ${ctx.verify_error}`);
        lines.push('');
        return lines.join('\n');
    }

    if (ctx.result) {
        lines.push(';; DNSSEC VERIFICATION:');
        lines.push(`;;   Verdict: ${ctx.result.verdict}`);

        if (ctx.result.insecureAt) {
            const reason = ctx.result.insecureReason ? ` (${ctx.result.insecureReason})` : '';
            lines.push(`;;   Insecure at: ${ctx.result.insecureAt}${reason}`);
        }
        if (ctx.result.bogusAt) {
            const reason = ctx.result.bogusReason ? ` (${ctx.result.bogusReason})` : '';
            lines.push(`;;   Bogus at: ${ctx.result.bogusAt}${reason}`);
        }
        if (ctx.result.negativeReason) {
            lines.push(`;;   Negative proof: ${ctx.result.negativeReason}`);
        }
        if (ctx.result.aliases && ctx.result.aliases.length > 0) {
            lines.push(`;;   Aliases:`);
            for (const a of ctx.result.aliases) lines.push(`;;     ${format_alias(a)}`);
        }
        if (ctx.result.wildcard) {
            const w = ctx.result.wildcard;
            lines.push(`;;   Wildcard: ${w.source} (closest=${w.closestEncloser}, next-closer=${w.nextCloser}, proof=${w.proofReason})`);
        }
        if (ctx.result.chain.length > 0) {
            lines.push(`;;   Chain:`);
            for (const step of ctx.result.chain) {
                lines.push(`;;     ${format_chain_step(step)}`);
            }
        }
        lines.push('');
    }

    return lines.join('\n');
}
