// Spec for resolver_auth.ts. Ports the dnsdata-go
// `resolver/auth/client_test.go` shape (UP-003 / #7) using real
// Node `dgram` / `net` listeners so the production NodeDialer is
// exercised end-to-end.

import * as dgram from 'dgram';
import * as net from 'net';
import {
    AuthClient,
    AuthNoServersError,
    AuthAllServersFailedError,
    AuthIDMismatchError,
    AuthResponseError,
    normalize_addr,
} from '../../src/lib/resolver_auth';
import { domain_name2wire, build_query_with_id } from '../../src/lib/dns_wire';

const TYPE_A = 1;
const TYPE_DNSKEY = 48;
const CLASS_IN = 1;

// --- Fixtures -----------------------------------------------------------

// build_response_to constructs a DNS response that copies the
// transaction ID from `query` so the auth client accepts it. Carries
// one answer RR (or none when the TC flag is set).
function build_response_to(
    query: Uint8Array,
    name: string,
    rrtype: number,
    ttl: number,
    rdata: Uint8Array,
    tc: boolean,
): Uint8Array {
    if (query.length < 12) throw new Error("query too short");
    const query_id = (query[0] << 8) | query[1];
    const qname = domain_name2wire(name);

    // Header: id, flags=0x8180 (QR|RD|RA, RCODE=0) [+ TC if requested],
    // QDCOUNT=1, ANCOUNT=(tc?0:1), NSCOUNT=0, ARCOUNT=0.
    const flags = tc ? 0x8180 | 0x0200 : 0x8180;
    const an_count = tc ? 0 : 1;

    const question_len = qname.length + 4;
    const answer_len = tc ? 0 : qname.length + 10 + rdata.length;
    const total = 12 + question_len + answer_len;

    const out = new Uint8Array(total);
    const view = new DataView(out.buffer);
    let p = 0;
    view.setUint16(p, query_id);  p += 2;
    view.setUint16(p, flags);     p += 2;
    view.setUint16(p, 1);         p += 2; // QDCOUNT
    view.setUint16(p, an_count);  p += 2;
    view.setUint16(p, 0);         p += 2;
    view.setUint16(p, 0);         p += 2;

    out.set(qname, p);            p += qname.length;
    view.setUint16(p, rrtype);    p += 2;
    view.setUint16(p, CLASS_IN);  p += 2;

    if (!tc) {
        out.set(qname, p);              p += qname.length;
        view.setUint16(p, rrtype);      p += 2;
        view.setUint16(p, CLASS_IN);    p += 2;
        view.setUint32(p, ttl);         p += 4;
        view.setUint16(p, rdata.length); p += 2;
        out.set(rdata, p);              p += rdata.length;
    }

    return out;
}

// build_response_with_authority builds a response carrying one answer
// + one authority record. Used to verify the Authority section
// survives resolve() so the verifier can locate NSEC / NSEC3 proofs.
function build_response_with_authority(
    query: Uint8Array,
    qname: string,
    qtype: number,
    answer_rdata: Uint8Array,
    auth_owner: string,
    auth_type: number,
    auth_rdata: Uint8Array,
): Uint8Array {
    const query_id = (query[0] << 8) | query[1];
    const qw = domain_name2wire(qname);
    const aw = domain_name2wire(auth_owner);

    const total =
        12 +
        qw.length + 4 + // question
        qw.length + 10 + answer_rdata.length + // answer RR
        aw.length + 10 + auth_rdata.length; // authority RR
    const out = new Uint8Array(total);
    const view = new DataView(out.buffer);
    let p = 0;
    view.setUint16(p, query_id);  p += 2;
    view.setUint16(p, 0x8180);    p += 2;
    view.setUint16(p, 1);         p += 2; // QDCOUNT
    view.setUint16(p, 1);         p += 2; // ANCOUNT
    view.setUint16(p, 1);         p += 2; // NSCOUNT
    view.setUint16(p, 0);         p += 2; // ARCOUNT

    out.set(qw, p);                       p += qw.length;
    view.setUint16(p, qtype);             p += 2;
    view.setUint16(p, CLASS_IN);          p += 2;

    out.set(qw, p);                       p += qw.length;
    view.setUint16(p, qtype);             p += 2;
    view.setUint16(p, CLASS_IN);          p += 2;
    view.setUint32(p, 60);                p += 4;
    view.setUint16(p, answer_rdata.length); p += 2;
    out.set(answer_rdata, p);             p += answer_rdata.length;

    out.set(aw, p);                       p += aw.length;
    view.setUint16(p, auth_type);         p += 2;
    view.setUint16(p, CLASS_IN);          p += 2;
    view.setUint32(p, 3600);              p += 4;
    view.setUint16(p, auth_rdata.length); p += 2;
    out.set(auth_rdata, p);               p += auth_rdata.length;

    return out;
}

// start_udp_listener spawns a UDP listener that reads one datagram
// and responds with the responder's bytes. Returns the listener's
// `host:port` address suitable for AuthClient.
function start_udp_listener(
    responder: (query: Uint8Array) => Uint8Array | null,
): Promise<{ addr: string; close: () => void }> {
    return new Promise((resolve, reject) => {
        const socket = dgram.createSocket('udp4');
        socket.once('error', (err) => reject(err));
        socket.once('listening', () => {
            const a = socket.address();
            resolve({
                addr: `${a.address}:${a.port}`,
                close: () => { try { socket.close(); } catch { /* ignore */ } },
            });
        });
        socket.on('message', (msg, rinfo) => {
            const resp = responder(new Uint8Array(msg));
            if (resp !== null) {
                socket.send(resp, rinfo.port, rinfo.address);
            }
        });
        socket.bind(0, '127.0.0.1');
    });
}

// start_udp_tcp_pair binds a UDP listener AND a TCP listener on the
// same `127.0.0.1:port` so the auth client can transparently retry
// over TCP after UDP TC. Returns the shared address and a close
// function. (Linux/macOS/Windows all let TCP and UDP coexist on
// identical ports because they're separate transport namespaces.)
function start_udp_tcp_pair(
    udp_responder: (query: Uint8Array) => Uint8Array,
    tcp_responder: (query: Uint8Array) => Uint8Array,
): Promise<{ addr: string; close: () => void }> {
    return new Promise((resolve, reject) => {
        const tcp = net.createServer((conn) => {
            let buf = Buffer.alloc(0);
            let need = -1;
            conn.on('data', (chunk: Buffer) => {
                buf = Buffer.concat([buf, chunk]);
                if (need < 0 && buf.length >= 2) {
                    need = buf.readUInt16BE(0);
                    buf = buf.slice(2);
                }
                if (need >= 0 && buf.length >= need) {
                    const query = new Uint8Array(buf.slice(0, need));
                    const resp = tcp_responder(query);
                    const out = Buffer.alloc(2 + resp.length);
                    out.writeUInt16BE(resp.length, 0);
                    Buffer.from(resp).copy(out, 2);
                    conn.write(out, () => conn.end());
                }
            });
            conn.on('error', () => { /* ignore */ });
        });
        tcp.once('error', (err) => reject(err));
        tcp.listen(0, '127.0.0.1', () => {
            const a = tcp.address() as net.AddressInfo;
            const udp = dgram.createSocket('udp4');
            udp.once('error', (err) => {
                tcp.close();
                reject(err);
            });
            udp.on('message', (msg, rinfo) => {
                const resp = udp_responder(new Uint8Array(msg));
                udp.send(resp, rinfo.port, rinfo.address);
            });
            udp.once('listening', () => {
                resolve({
                    addr: `${a.address}:${a.port}`,
                    close: () => {
                        try { udp.close(); } catch { /* ignore */ }
                        tcp.close();
                    },
                });
            });
            udp.bind(a.port, '127.0.0.1');
        });
    });
}

// --- Tests --------------------------------------------------------------

describe("AuthClient (UP-003)", () => {
    it("throws AuthNoServersError when no servers are configured", async () => {
        const c = new AuthClient();
        await expect(c.query("example.com.", TYPE_A)).rejects.toBeInstanceOf(AuthNoServersError);
    });

    it("returns a response over UDP on the happy path", async () => {
        const server = await start_udp_listener((q) =>
            build_response_to(q, "example.com.", TYPE_A, 300, new Uint8Array([192, 0, 2, 1]), false),
        );
        try {
            const c = new AuthClient({ servers: [server.addr], timeout_ms: 500 });
            const resp = await c.query("example.com.", TYPE_A);
            expect(resp.length).toBeGreaterThan(12);
            // QR bit (0x80 of byte 2) must be set in the response.
            expect(resp[2] & 0x80).not.toBe(0);
        } finally {
            server.close();
        }
    });

    it("falls back to TCP when the UDP response has the TC bit set", async () => {
        const server = await start_udp_tcp_pair(
            (q) => build_response_to(q, "example.com.", TYPE_A, 300, new Uint8Array([192, 0, 2, 5]), true /*TC*/),
            (q) => build_response_to(q, "example.com.", TYPE_A, 300, new Uint8Array([192, 0, 2, 5]), false),
        );
        try {
            const c = new AuthClient({ servers: [server.addr], timeout_ms: 500 });
            const resp = await c.query("example.com.", TYPE_A);
            expect(resp.length).toBeGreaterThan(12);
            // TCP response: TC bit must be clear.
            expect(resp[2] & 0x02).toBe(0);
        } finally {
            server.close();
        }
    });

    it("fails over to the next server when the first times out", async () => {
        const dead = await start_udp_listener(() => null); // never responds
        const good = await start_udp_listener((q) =>
            build_response_to(q, "example.com.", TYPE_A, 300, new Uint8Array([192, 0, 2, 9]), false),
        );
        try {
            const c = new AuthClient({
                servers: [dead.addr, good.addr],
                timeout_ms: 150,
            });
            const resp = await c.query("example.com.", TYPE_A);
            expect(resp.length).toBeGreaterThan(12);
        } finally {
            dead.close();
            good.close();
        }
    });

    it("throws AuthAllServersFailedError when every server fails", async () => {
        const dead = await start_udp_listener(() => null);
        try {
            const c = new AuthClient({
                servers: [dead.addr, dead.addr],
                timeout_ms: 150,
            });
            await expect(c.query("example.com.", TYPE_A)).rejects.toBeInstanceOf(AuthAllServersFailedError);
        } finally {
            dead.close();
        }
    });

    it("rejects responses with a mismatched transaction ID", async () => {
        const server = await start_udp_listener((q) => {
            const resp = build_response_to(q, "example.com.", TYPE_A, 300, new Uint8Array([192, 0, 2, 1]), false);
            // Overwrite the ID.
            resp[0] = 0xDE;
            resp[1] = 0xAD;
            return resp;
        });
        try {
            const c = new AuthClient({ servers: [server.addr], timeout_ms: 300 });
            // With only one server, the inner ID-mismatch wraps into
            // AuthAllServersFailedError. Both are observable.
            const failure = c.query("example.com.", TYPE_A);
            await expect(failure).rejects.toBeInstanceOf(AuthAllServersFailedError);
            await failure.catch((err: AuthAllServersFailedError) => {
                expect(err.cause).toBeInstanceOf(AuthIDMismatchError);
            });
        } finally {
            server.close();
        }
    });

    it("resolve() parses an answer RR (DNSKEY) into ResourceRecord", async () => {
        // Build a DNSKEY rdata: flags=257 (KSK), proto=3, algo=13, key=0xdeadbeef.
        const key = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
        const rdata = new Uint8Array(4 + key.length);
        rdata[0] = 0x01; rdata[1] = 0x01; // flags=257
        rdata[2] = 3;
        rdata[3] = 13;
        rdata.set(key, 4);

        const server = await start_udp_listener((q) =>
            build_response_to(q, "example.com.", TYPE_DNSKEY, 3600, rdata, false),
        );
        try {
            const c = new AuthClient({ servers: [server.addr], timeout_ms: 500 });
            const records = await c.resolve("example.com.", TYPE_DNSKEY);
            expect(records.length).toBe(1);
            expect(records[0].value).toBe("257 3 13 3q2+7w==");
        } finally {
            server.close();
        }
    });

    it("resolve() includes the authority section for NSEC / NSEC3 proofs", async () => {
        const ns_target = domain_name2wire("ns.example.com.");
        const TYPE_NS = 2;
        const server = await start_udp_listener((q) =>
            build_response_with_authority(
                q, "www.example.com.", TYPE_A,
                new Uint8Array([192, 0, 2, 1]),
                "example.com.", TYPE_NS, ns_target,
            ),
        );
        try {
            const c = new AuthClient({ servers: [server.addr], timeout_ms: 500 });
            const records = await c.resolve("www.example.com.", TYPE_A);
            expect(records.length).toBe(2);
            expect(records[0].label).toBe("www.example.com.");
            expect(records[1].label).toBe("example.com.");
        } finally {
            server.close();
        }
    });

    it("resolve() throws AuthResponseError on non-zero RCODE", async () => {
        const server = await start_udp_listener((q) => {
            // Build NXDOMAIN response: flags = 0x8183 (QR|RD|RA|RCODE=3).
            const query_id = (q[0] << 8) | q[1];
            const qname = domain_name2wire("missing.example.");
            const out = new Uint8Array(12 + qname.length + 4);
            const view = new DataView(out.buffer);
            view.setUint16(0, query_id);
            view.setUint16(2, 0x8183);
            view.setUint16(4, 1);
            view.setUint16(6, 0);
            view.setUint16(8, 0);
            view.setUint16(10, 0);
            out.set(qname, 12);
            view.setUint16(12 + qname.length, TYPE_A);
            view.setUint16(12 + qname.length + 2, CLASS_IN);
            return out;
        });
        try {
            const c = new AuthClient({ servers: [server.addr], timeout_ms: 500 });
            await expect(c.resolve("missing.example.", TYPE_A)).rejects.toBeInstanceOf(AuthResponseError);
        } finally {
            server.close();
        }
    });

    it("servers() returns a defensive copy", () => {
        const c = new AuthClient({ servers: ["1.2.3.4:53", "5.6.7.8:53"] });
        const list = c.servers();
        list[0] = "tampered";
        expect(c.servers()[0]).toBe("1.2.3.4:53");
    });

    it("clamps udp_buffer_size below 512 up to 512", async () => {
        // The client must still succeed even when a smaller buffer was
        // requested — the clamp guarantees we never under-size the
        // minimum DNS UDP message.
        const server = await start_udp_listener((q) =>
            build_response_to(q, "example.com.", TYPE_A, 300, new Uint8Array([192, 0, 2, 1]), false),
        );
        try {
            const c = new AuthClient({
                servers: [server.addr],
                timeout_ms: 500,
                udp_buffer_size: 100,
            });
            const resp = await c.query("example.com.", TYPE_A);
            expect(resp.length).toBeGreaterThan(12);
        } finally {
            server.close();
        }
    });

    it("works with a directly-built query message via query_raw", async () => {
        const server = await start_udp_listener((q) =>
            build_response_to(q, "example.com.", TYPE_A, 300, new Uint8Array([192, 0, 2, 1]), false),
        );
        try {
            const c = new AuthClient({ servers: [server.addr], timeout_ms: 500 });
            const id = 0xABCD;
            const msg = build_query_with_id(id, "example.com.", TYPE_A);
            const resp = await c.query_raw(id, msg);
            expect(resp.length).toBeGreaterThan(12);
            expect((resp[0] << 8) | resp[1]).toBe(id);
        } finally {
            server.close();
        }
    });
});

describe("normalize_addr (UP-003)", () => {
    const cases: Array<[string, string]> = [
        ["1.2.3.4",       "1.2.3.4:53"],
        ["1.2.3.4:5353",  "1.2.3.4:5353"],
        ["[::1]:53",      "[::1]:53"],
        ["::1",           "[::1]:53"],
    ];
    it.each(cases)("normalize_addr(%s) -> %s", (input, expected) => {
        expect(normalize_addr(input)).toBe(expected);
    });
});
