export interface DNSAnswer {
    name: string;    // FQDN (trailing dot)
    type: number;    // numeric RR type
    TTL: number;
    data: string;    // presentation format
}

export interface DNSResponse {
    status: number;       // DNS rcode
    answers: DNSAnswer[];
    authority: DNSAnswer[];
}

export interface Resolver {
    resolve(fqdn: string, rrtype: number): Promise<DNSResponse>;
}
