// Ports dnsdata-go `resolver/dot/client_test.go`: the DoT client
// against a Node `tls` server with a self-signed certificate.

import * as net from 'net';
import * as tls from 'tls';
import {
    DoTAllServersFailedError,
    DoTClient,
    DoTIDMismatchError,
    DoTNoServersError,
    DoTResolverError,
    DoTResponseTooShortError,
    normalize_dot_addr,
} from '../../../src/resolver/dot';
import { parse_message } from '../../../src/wire/dns_message';
import { domain_name2wire, FLAG_CD } from '../../../src/wire/dns_wire';
import { TEST_CERT_PEM, TEST_KEY_PEM, TEST_SERVER_NAME } from './fixtures';

const TYPE_A = 1;
const CLASS_IN = 1;
const RCODE_NXDOMAIN = 3;
const TIMEOUT_MS = 2000;

type Responder = (query: Uint8Array) => Uint8Array;

const servers: tls.Server[] = [];

afterEach(async () => {
    await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

// start_dot_server serves DNS over TLS on 127.0.0.1: each connection
// gets one length-prefixed query and the responder's reply.
async function start_dot_server(responder: Responder): Promise<string> {
    const server = tls.createServer({ key: TEST_KEY_PEM, cert: TEST_CERT_PEM }, (socket) => {
        let buf = Buffer.alloc(0);
        socket.on('data', (data: Buffer) => {
            buf = Buffer.concat([buf, data]);
            if (buf.length < 2 || buf.length < 2 + buf.readUInt16BE(0)) return;
            const resp = Buffer.from(responder(new Uint8Array(buf.subarray(2, 2 + buf.readUInt16BE(0)))));
            const len = Buffer.alloc(2);
            len.writeUInt16BE(resp.length);
            socket.end(Buffer.concat([len, resp]));
        });
        socket.on('error', () => { /* client gave up; nothing to do */ });
    });
    servers.push(server);
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    return `127.0.0.1:${(server.address() as net.AddressInfo).port}`;
}

// answer_a replies to query with one A record (192.0.2.1) for its question.
function answer_a(query: Uint8Array, rcode = 0): Uint8Array {
    const qname = domain_name2wire(parse_message(query).question.name);
    const rdata = [192, 0, 2, 1];
    const out = Buffer.alloc(12 + 2 * (qname.length + 4) + 6 + rdata.length);
    let p = out.writeUInt16BE((query[0] << 8) | query[1], 0);
    p = out.writeUInt16BE(0x8180 | rcode, p);
    for (const count of [1, 1, 0, 0]) p = out.writeUInt16BE(count, p);
    for (let i = 0; i < 2; i++) {
        out.set(qname, p);
        p = out.writeUInt16BE(TYPE_A, p + qname.length);
        p = out.writeUInt16BE(CLASS_IN, p);
    }
    p = out.writeUInt32BE(300, p);
    p = out.writeUInt16BE(rdata.length, p);
    out.set(rdata, p);
    return new Uint8Array(out);
}

function client(...addrs: string[]): DoTClient {
    return new DoTClient({ servers: addrs, tls: { ca: TEST_CERT_PEM }, timeout_ms: TIMEOUT_MS });
}

describe('DoTClient', () => {
    it('resolves an answer', async () => {
        const addr = await start_dot_server((q) => answer_a(q));
        const resp = await client(addr).resolve('www.example.com.', TYPE_A);
        expect(resp.rcode).toBe(0);
        expect(resp.records.map((rr) => rr.value)).toEqual(['192.0.2.1']);
    });

    it('returns a non-zero RCODE as data', async () => {
        const addr = await start_dot_server((q) => answer_a(q, RCODE_NXDOMAIN));
        expect((await client(addr).resolve('nope.example.com.', TYPE_A)).rcode).toBe(RCODE_NXDOMAIN);
    });

    // RFC 8310 strict privacy: the certificate must chain to a trusted
    // root and match the name (or address) the client expects.
    it.each([
        ['untrusted root', {}],
        ['name mismatch', { ca: TEST_CERT_PEM, servername: 'other.test' }],
    ] as [string, { ca?: string; servername?: string }][])('rejects the server: %s', async (_name, tls_options) => {
        const addr = await start_dot_server((q) => answer_a(q));
        const c = new DoTClient({ servers: [addr], tls: tls_options, timeout_ms: TIMEOUT_MS });
        const err = await c.query('www.example.com.', TYPE_A).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(DoTAllServersFailedError);
        expect(err).toBeInstanceOf(DoTResolverError);
    });

    it('accepts a certificate for the configured server name', async () => {
        const addr = await start_dot_server((q) => answer_a(q));
        const c = new DoTClient({ servers: [addr], tls: { ca: TEST_CERT_PEM, servername: TEST_SERVER_NAME } });
        await expect(c.query('www.example.com.', TYPE_A)).resolves.toBeInstanceOf(Uint8Array);
    });

    it.each([false, true])('puts CD=%s on the wire', async (cd) => {
        let bit: boolean | null = null;
        const addr = await start_dot_server((q) => {
            bit = (((q[2] << 8) | q[3]) & FLAG_CD) !== 0;
            return answer_a(q);
        });
        const c = new DoTClient({ servers: [addr], tls: { ca: TEST_CERT_PEM }, checking_disabled: cd });
        await c.query('www.example.com.', TYPE_A);
        expect(bit).toBe(cd);
    });

    it('fails over to the next server', async () => {
        const dead = net.createServer();
        await new Promise<void>((r) => dead.listen(0, '127.0.0.1', r));
        const dead_addr = `127.0.0.1:${(dead.address() as net.AddressInfo).port}`;
        await new Promise((r) => dead.close(r));
        const addr = await start_dot_server((q) => answer_a(q));
        await expect(client(dead_addr, addr).query('www.example.com.', TYPE_A)).resolves.toBeInstanceOf(Uint8Array);
    });

    it('rejects a reply to another query', async () => {
        const addr = await start_dot_server((q) => {
            const resp = answer_a(q);
            resp[0] ^= 0xff;
            return resp;
        });
        const err = (await client(addr).query('www.example.com.', TYPE_A).catch((e: unknown) => e)) as DoTAllServersFailedError;
        expect(err.cause).toBeInstanceOf(DoTIDMismatchError);
    });

    it('rejects a reply shorter than a header', async () => {
        const addr = await start_dot_server(() => new Uint8Array([0, 1, 2]));
        const err = (await client(addr).query('www.example.com.', TYPE_A).catch((e: unknown) => e)) as DoTAllServersFailedError;
        expect(err.cause).toBeInstanceOf(DoTResponseTooShortError);
    });

    it('needs a server', async () => {
        await expect(new DoTClient().query('example.com.', TYPE_A)).rejects.toBeInstanceOf(DoTNoServersError);
    });

    it('stops on an aborted signal', async () => {
        const addr = await start_dot_server((q) => answer_a(q));
        const ac = new AbortController();
        ac.abort();
        await expect(client(addr).query('www.example.com.', TYPE_A, { signal: ac.signal })).rejects.toBeInstanceOf(DoTResolverError);
    });

    it('copies its server list', () => {
        const c = new DoTClient({ servers: ['192.0.2.1'] });
        c.servers()[0] = 'changed';
        expect(c.servers()).toEqual(['192.0.2.1:853']);
    });
});

describe('normalize_dot_addr', () => {
    it.each([
        ['192.0.2.1', '192.0.2.1:853'],
        ['192.0.2.1:8853', '192.0.2.1:8853'],
        ['dns.example', 'dns.example:853'],
        ['[2001:db8::1]:5', '[2001:db8::1]:5'],
        ['2001:db8::1', '[2001:db8::1]:853'],
    ])('%s → %s', (input, want) => {
        expect(normalize_dot_addr(input)).toBe(want);
    });
});
