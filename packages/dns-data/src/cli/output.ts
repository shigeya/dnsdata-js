import { DNSAnswer, DNSResponse } from './resolver';
import { RRTypeToString, RCodeToString } from '../lib/dns_type_table';
import { VerificationResult } from './dnssec_verifier';

export interface OutputOptions {
    fqdn: string;
    rrtype: string;
    method: string;
    provider?: string;
}

function padRight(s: string, len: number): string {
    return s.length >= len ? s : s + ' '.repeat(len - s.length);
}

function formatAnswer(ans: DNSAnswer): string {
    const typeName = (() => {
        try { return RRTypeToString(ans.type); }
        catch { return String(ans.type); }
    })();
    return `${padRight(ans.name, 24)} ${String(ans.TTL).padStart(6)}  IN  ${padRight(typeName, 8)} ${ans.data}`;
}

export function formatOutput(
    opts: OutputOptions,
    response: DNSResponse,
    verification?: VerificationResult,
): string {
    const lines: string[] = [];

    const rcodeStr = (() => {
        try { return RCodeToString(response.status); }
        catch { return String(response.status); }
    })();

    const methodDesc = opts.method === 'doh'
        ? `DoH (${opts.provider || 'google'})`
        : 'DNS (system resolver)';

    lines.push(`; <<>> dnsjs lookup <<>> ${opts.fqdn} ${opts.rrtype}`);
    lines.push(`;; Method: ${methodDesc}`);
    lines.push(`;; Status: ${rcodeStr}`);
    lines.push('');

    if (response.answers.length > 0) {
        lines.push(';; ANSWER SECTION:');
        for (const ans of response.answers) {
            lines.push(formatAnswer(ans));
        }
        lines.push('');
    }

    if (response.authority.length > 0) {
        lines.push(';; AUTHORITY SECTION:');
        for (const ans of response.authority) {
            lines.push(formatAnswer(ans));
        }
        lines.push('');
    }

    if (response.answers.length === 0 && response.authority.length === 0) {
        lines.push(';; No records found.');
        lines.push('');
    }

    if (verification) {
        // Check if details already contain a Result line (chain verification)
        const hasResult = verification.details.some(d => d.startsWith('Result:'));
        lines.push(hasResult ? ';; DNSSEC VERIFICATION (chain):' : ';; DNSSEC VERIFICATION:');
        for (const detail of verification.details) {
            lines.push(`;;   ${detail}`);
        }
        if (!hasResult) {
            lines.push(`;;   Result: ${verification.verified ? 'SECURE' : 'INSECURE'}`);
        }
        lines.push('');
    }

    return lines.join('\n');
}
