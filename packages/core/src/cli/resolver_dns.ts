import * as dns from 'dns';
import { DNSAnswer, DNSResponse, Resolver } from './resolver';
import { RRTypeToString } from '../lib/dns_type_table';
import { errCode } from './error_util';

function ensureTrailingDot(name: string): string {
    return name.endsWith('.') ? name : name + '.';
}

function makeDNSAnswer(name: string, type: number, data: string): DNSAnswer {
    return { name: ensureTrailingDot(name), type, TTL: 0, data };
}

export class DNSResolver implements Resolver {
    private resolver = new dns.promises.Resolver();

    async resolve(fqdn: string, rrtype: number): Promise<DNSResponse> {
        const typeName = RRTypeToString(rrtype);
        const name = fqdn.endsWith('.') ? fqdn.slice(0, -1) : fqdn;

        try {
            const answers = await this.resolveByType(name, rrtype, typeName);
            return { status: 0, answers, authority: [] };
        } catch (err: unknown) {
            const code = errCode(err);
            if (code === 'ENOTFOUND' || code === 'ENODATA') {
                return { status: 0, answers: [], authority: [] };
            }
            if (code === 'ESERVFAIL') {
                return { status: 2, answers: [], authority: [] };
            }
            throw err;
        }
    }

    private async resolveByType(name: string, rrtype: number, typeName: string): Promise<DNSAnswer[]> {
        const fqdnDot = name + '.';
        switch (typeName) {
            case 'A': {
                const addrs = await this.resolver.resolve4(name);
                return addrs.map(a => makeDNSAnswer(fqdnDot, rrtype, a));
            }
            case 'AAAA': {
                const addrs = await this.resolver.resolve6(name);
                return addrs.map(a => makeDNSAnswer(fqdnDot, rrtype, a));
            }
            case 'MX': {
                const records = await this.resolver.resolveMx(name);
                return records.map(r => makeDNSAnswer(fqdnDot, rrtype, `${r.priority} ${r.exchange}.`));
            }
            case 'TXT': {
                const records = await this.resolver.resolveTxt(name);
                return records.map(r => makeDNSAnswer(fqdnDot, rrtype, r.map(s => `"${s}"`).join(' ')));
            }
            case 'NS': {
                const records = await this.resolver.resolveNs(name);
                return records.map(r => makeDNSAnswer(fqdnDot, rrtype, ensureTrailingDot(r)));
            }
            case 'CNAME': {
                const records = await this.resolver.resolveCname(name);
                return records.map(r => makeDNSAnswer(fqdnDot, rrtype, ensureTrailingDot(r)));
            }
            case 'SOA': {
                const r = await this.resolver.resolveSoa(name);
                return [makeDNSAnswer(fqdnDot, rrtype,
                    `${ensureTrailingDot(r.nsname)} ${ensureTrailingDot(r.hostmaster)} ${r.serial} ${r.refresh} ${r.retry} ${r.expire} ${r.minttl}`)];
            }
            case 'PTR': {
                const records = await this.resolver.resolvePtr(name);
                return records.map(r => makeDNSAnswer(fqdnDot, rrtype, ensureTrailingDot(r)));
            }
            case 'SRV': {
                const records = await this.resolver.resolveSrv(name);
                return records.map(r => makeDNSAnswer(fqdnDot, rrtype,
                    `${r.priority} ${r.weight} ${r.port} ${ensureTrailingDot(r.name)}`));
            }
            case 'CAA': {
                const records = await this.resolver.resolveCaa(name);
                return records.map(r => makeDNSAnswer(fqdnDot, rrtype,
                    `${r.critical ? 128 : 0} ${r.issue ? 'issue' : r.iodef ? 'iodef' : 'issue'} "${r.issue || r.iodef || ''}"`));
            }
            default:
                // dns module cannot resolve DNSKEY, RRSIG, DS, NSEC, NSEC3, etc.
                throw new Error(`dns module cannot resolve type ${typeName}. Use --method doh instead.`);
        }
    }
}
