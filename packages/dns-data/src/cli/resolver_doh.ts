import * as https from 'https';
import { DNSAnswer, DNSResponse, Resolver } from './resolver';
import { RRTypeToString } from '../lib/dns_type_table';

export type DoHProvider = 'google' | 'cloudflare';

interface DoHJsonAnswer {
    name: string;
    type: number;
    TTL: number;
    data: string;
}

interface DoHJsonResponse {
    Status: number;
    Answer?: DoHJsonAnswer[];
    Authority?: DoHJsonAnswer[];
}

function buildUrl(provider: DoHProvider, fqdn: string, rrtype: number): string {
    const typeName = RRTypeToString(rrtype);
    if (provider === 'cloudflare') {
        return `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(fqdn)}&type=${typeName}&do=1&cd=1`;
    }
    return `https://dns.google/resolve?name=${encodeURIComponent(fqdn)}&type=${typeName}&do=1&cd=1`;
}

function getHeaders(provider: DoHProvider): Record<string, string> {
    if (provider === 'cloudflare') {
        return { 'Accept': 'application/dns-json' };
    }
    return {};
}

function httpsGet(url: string, headers: Record<string, string>): Promise<string> {
    return new Promise((resolve, reject) => {
        const req = https.get(url, { headers }, (res) => {
            if (res.statusCode !== 200) {
                reject(new Error(`HTTP ${res.statusCode} from ${url}`));
                res.resume();
                return;
            }
            const chunks: Buffer[] = [];
            res.on('data', (chunk: Buffer) => chunks.push(chunk));
            res.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
        });
        req.on('error', reject);
        req.setTimeout(10000, () => {
            req.destroy(new Error('Request timeout'));
        });
    });
}

function ensureTrailingDot(name: string): string {
    return name.endsWith('.') ? name : name + '.';
}

function convertAnswer(ans: DoHJsonAnswer): DNSAnswer {
    return {
        name: ensureTrailingDot(ans.name),
        type: ans.type,
        TTL: ans.TTL,
        data: ans.data,
    };
}

export class DoHResolver implements Resolver {
    constructor(private provider: DoHProvider = 'google') {}

    async resolve(fqdn: string, rrtype: number): Promise<DNSResponse> {
        const url = buildUrl(this.provider, fqdn, rrtype);
        const headers = getHeaders(this.provider);
        const body = await httpsGet(url, headers);
        const json: DoHJsonResponse = JSON.parse(body);

        return {
            status: json.Status,
            answers: (json.Answer || []).map(convertAnswer),
            authority: (json.Authority || []).map(convertAnswer),
        };
    }
}
