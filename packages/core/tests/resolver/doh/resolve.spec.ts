// Spec for DoHClient.resolve. Ports
// dnsdata-go/resolver/doh/resolve_test.go (UP-007).

import * as http from 'http';
import { AddressInfo } from 'net';
import {
    DoHClient,
    DOH_MEDIA_TYPE,
} from '../../../src/resolver/doh/client';
import { DoHResponseError } from '../../../src/resolver/doh/errors';
// Importing resolve.ts has the side-effect of installing
// DoHClient.prototype.resolve. The barrel does it too — this spec
// imports it directly so the test exercises the file under test.
import '../../../src/resolver/doh/resolve';
import { domain_name2wire } from '../../../src/wire/dns_wire';
import { WireBuilder } from '../../../src/wire/dns_wire_util';

const TYPE_A = 1;
const TYPE_NS = 2;
const TYPE_DNSKEY = 48;
const CLASS_IN = 1;

interface StubServer {
    url: string;
    close: () => Promise<void>;
}

function start_server(response_bytes: Buffer): Promise<StubServer> {
    return new Promise((resolve, reject) => {
        const server = http.createServer((req, res) => {
            // Drain request body so the connection can be reused.
            req.on('data', () => { /* drain */ });
            req.on('end', () => {
                res.setHeader('Content-Type', DOH_MEDIA_TYPE);
                res.end(response_bytes);
            });
        });
        server.once('error', reject);
        server.listen(0, '127.0.0.1', () => {
            const addr = server.address() as AddressInfo;
            resolve({
                url: `http://127.0.0.1:${addr.port}/dns-query`,
                close: () => new Promise<void>((res) => server.close(() => res())),
            });
        });
    });
}

// Build a tiny DNS response carrying one answer record. Question
// section matches the answer's name + type. No compression.
function build_response(
    name: string,
    rrtype: number,
    ttl: number,
    rdata: Uint8Array,
): Buffer {
    const b = new WireBuilder();
    b.append_uint16(0x1234);       // ID
    b.append_uint16(0x8180);       // flags: QR=1, RD=1, RA=1, RCODE=0
    b.append_uint16(1);            // QDCOUNT
    b.append_uint16(1);            // ANCOUNT
    b.append_uint16(0);            // NSCOUNT
    b.append_uint16(0);            // ARCOUNT
    const name_wire = domain_name2wire(name);
    b.append_bytes(name_wire);
    b.append_uint16(rrtype);
    b.append_uint16(CLASS_IN);
    b.append_bytes(name_wire);
    b.append_uint16(rrtype);
    b.append_uint16(CLASS_IN);
    b.append_uint32(ttl);
    b.append_uint16(rdata.length);
    b.append_bytes(rdata);
    return Buffer.from(b.build());
}

function build_response_rcode(name: string, rrtype: number, rcode: number): Buffer {
    const b = new WireBuilder();
    b.append_uint16(0x1234);
    b.append_uint16(0x8180 | (rcode & 0x0F));
    b.append_uint16(1);
    b.append_uint16(0); // ANCOUNT
    b.append_uint16(0);
    b.append_uint16(0);
    const name_wire = domain_name2wire(name);
    b.append_bytes(name_wire);
    b.append_uint16(rrtype);
    b.append_uint16(CLASS_IN);
    return Buffer.from(b.build());
}

function build_response_with_authority(
    qname: string, qtype: number,
    answer_owner: string, answer_type: number, answer_ttl: number, answer_rdata: Uint8Array,
    auth_owner: string, auth_type: number, auth_ttl: number, auth_rdata: Uint8Array,
): Buffer {
    const b = new WireBuilder();
    b.append_uint16(0x1234);
    b.append_uint16(0x8180);
    b.append_uint16(1); // QDCOUNT
    b.append_uint16(1); // ANCOUNT
    b.append_uint16(1); // NSCOUNT
    b.append_uint16(0); // ARCOUNT
    const qw = domain_name2wire(qname);
    b.append_bytes(qw);
    b.append_uint16(qtype);
    b.append_uint16(CLASS_IN);

    const aw = domain_name2wire(answer_owner);
    b.append_bytes(aw);
    b.append_uint16(answer_type);
    b.append_uint16(CLASS_IN);
    b.append_uint32(answer_ttl);
    b.append_uint16(answer_rdata.length);
    b.append_bytes(answer_rdata);

    const auw = domain_name2wire(auth_owner);
    b.append_bytes(auw);
    b.append_uint16(auth_type);
    b.append_uint16(CLASS_IN);
    b.append_uint32(auth_ttl);
    b.append_uint16(auth_rdata.length);
    b.append_bytes(auth_rdata);
    return Buffer.from(b.build());
}

function hex_to_bytes(hex: string): Uint8Array {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
}

function dnskey_rdata(flags: number, protocol: number, algorithm: number, key_hex: string): Uint8Array {
    const key = hex_to_bytes(key_hex);
    const out = new Uint8Array(4 + key.length);
    out[0] = (flags >> 8) & 0xff;
    out[1] = flags & 0xff;
    out[2] = protocol;
    out[3] = algorithm;
    out.set(key, 4);
    return out;
}

describe('DoHClient.resolve', () => {
    let servers: StubServer[] = [];

    afterEach(async () => {
        await Promise.all(servers.map((s) => s.close()));
        servers = [];
    });

    function track(s: StubServer): StubServer {
        servers.push(s);
        return s;
    }

    test('parses a DNSKEY answer back to presentation form', async () => {
        const rdata = dnskey_rdata(257, 3, 13, 'deadbeef');
        const response = build_response('example.com.', TYPE_DNSKEY, 3600, rdata);
        const srv = track(await start_server(response));

        const c = new DoHClient({ providers: [srv.url], timeout_ms: 2000 });
        const resp = await c.resolve('example.com.', TYPE_DNSKEY);
        expect(resp.rcode).toBe(0);
        const records = resp.records;
        expect(records).toHaveLength(1);
        const rr = records[0];
        expect(rr.label).toBe('example.com.');
        expect(rr.type).toBe(TYPE_DNSKEY);
        expect(rr.ttl).toBe(3600);
        expect(rr.value).toBe('257 3 13 3q2+7w==');
    });

    test('surfaces the authority section so the verifier can find negative proofs', async () => {
        const answer_rdata = new Uint8Array([192, 0, 2, 1]);
        const ns_target = domain_name2wire('ns.example.com.');
        const response = build_response_with_authority(
            'www.example.com.', TYPE_A,
            'www.example.com.', TYPE_A, 60, answer_rdata,
            'example.com.', TYPE_NS, 3600, ns_target,
        );
        const srv = track(await start_server(response));

        const c = new DoHClient({ providers: [srv.url], timeout_ms: 2000 });
        const resp = await c.resolve('www.example.com.', TYPE_A);
        const records = resp.records;
        expect(records).toHaveLength(2);
        expect(records[0].type).toBe(TYPE_A);
        expect(records[0].label).toBe('www.example.com.');
        expect(records[1].type).toBe(TYPE_NS);
        expect(records[1].label).toBe('example.com.');
    });

    test('surfaces non-zero RCODE as data, not as an error', async () => {
        const response = build_response_rcode('missing.example.', TYPE_A, 3); // NXDOMAIN
        const srv = track(await start_server(response));
        const c = new DoHClient({ providers: [srv.url], timeout_ms: 2000 });
        const resp = await c.resolve('missing.example.', TYPE_A);
        expect(resp.rcode).toBe(3);
        expect(resp.records).toHaveLength(0);
    });

    test('rejects a malformed response with DoHResponseError', async () => {
        const srv = track(await start_server(Buffer.from([0x00, 0x01, 0x02])));
        const c = new DoHClient({ providers: [srv.url], timeout_ms: 2000 });
        await expect(c.resolve('example.com.', TYPE_A)).rejects.toBeInstanceOf(DoHResponseError);
    });
});
