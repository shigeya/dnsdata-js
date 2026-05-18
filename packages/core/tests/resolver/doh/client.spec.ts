// Spec for the DoH client transport. Ports
// dnsdata-go/resolver/doh/client_test.go (UP-007).
//
// Tests boot a real Node `http` listener so the production fetch
// path is exercised end-to-end; the only thing not exercised is TLS,
// which lives below `fetch`'s API and is the runtime's concern.

import * as http from 'http';
import { AddressInfo } from 'net';
import {
    DoHClient,
    DOH_MEDIA_TYPE,
    default_providers,
} from '../../../src/resolver/doh/client';
import {
    DoHAllProvidersFailedError,
    DoHNoProvidersError,
    DoHUnexpectedContentTypeError,
    DoHUnexpectedStatusError,
    DoHTransportError,
} from '../../../src/resolver/doh/errors';

const TYPE_A = 1;

// stubResponse is what the mock server returns on success. The bytes
// are not a valid DNS message — the doh package returns them as-is
// and leaves parsing to a higher layer (parse_message).
const STUB_RESPONSE = new Uint8Array([
    0x12, 0x34, // ID
    0x81, 0x80, // flags (QR=1, RD=1, RA=1)
    0x00, 0x01, // QDCOUNT
    0x00, 0x00, // ANCOUNT
    0x00, 0x00, // NSCOUNT
    0x00, 0x00, // ARCOUNT
]);

interface StubServer {
    url: string;
    close: () => Promise<void>;
}

type Handler = (req: http.IncomingMessage, res: http.ServerResponse, body: Buffer) => void;

function start_server(handler: Handler): Promise<StubServer> {
    return new Promise((resolve, reject) => {
        const server = http.createServer((req, res) => {
            const chunks: Buffer[] = [];
            req.on('data', (chunk: Buffer) => chunks.push(chunk));
            req.on('end', () => handler(req, res, Buffer.concat(chunks)));
            req.on('error', () => res.destroy());
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

// Default stub: accepts POST with the right Content-Type and returns
// STUB_RESPONSE with the right Content-Type.
function ok_handler(req: http.IncomingMessage, res: http.ServerResponse): void {
    if (req.method !== 'POST') {
        res.statusCode = 405;
        res.end('method');
        return;
    }
    if (req.headers['content-type'] !== DOH_MEDIA_TYPE) {
        res.statusCode = 415;
        res.end('content-type');
        return;
    }
    res.setHeader('Content-Type', DOH_MEDIA_TYPE);
    res.end(Buffer.from(STUB_RESPONSE));
}

describe('DoHClient transport', () => {
    let servers: StubServer[] = [];

    afterEach(async () => {
        await Promise.all(servers.map((s) => s.close()));
        servers = [];
    });

    function track(s: StubServer): StubServer {
        servers.push(s);
        return s;
    }

    test('query returns response bytes from a successful provider', async () => {
        const srv = track(await start_server(ok_handler));
        const c = new DoHClient({ providers: [srv.url], timeout_ms: 2000 });
        const out = await c.query('example.com.', TYPE_A);
        expect(Array.from(out)).toEqual(Array.from(STUB_RESPONSE));
    });

    test('query_raw fails over from a 5xx provider to a healthy one', async () => {
        const bad = track(await start_server((_req, res) => {
            res.statusCode = 500;
            res.end('boom');
        }));
        const good = track(await start_server(ok_handler));

        const c = new DoHClient({ providers: [bad.url, good.url], timeout_ms: 2000 });
        const out = await c.query('example.com.', TYPE_A);
        expect(Array.from(out)).toEqual(Array.from(STUB_RESPONSE));
    });

    test('query_raw throws DoHAllProvidersFailedError when every provider 5xxes', async () => {
        const bad = track(await start_server((_req, res) => {
            res.statusCode = 500;
            res.end('boom');
        }));
        const c = new DoHClient({ providers: [bad.url, bad.url], timeout_ms: 2000 });
        let err: unknown;
        try {
            await c.query('example.com.', TYPE_A);
        } catch (e) {
            err = e;
        }
        expect(err).toBeInstanceOf(DoHAllProvidersFailedError);
        expect((err as DoHAllProvidersFailedError).cause).toBeInstanceOf(DoHUnexpectedStatusError);
    });

    test('empty providers list normalises to the default three', () => {
        const c = new DoHClient({ providers: [] });
        const ps = c.providers();
        expect(ps).toHaveLength(3);
    });

    test('omitted providers normalises to the default three', () => {
        const c = new DoHClient();
        expect(c.providers()).toHaveLength(3);
    });

    test('query_raw with empty bytes is still posted (HTTP layer is happy)', async () => {
        const srv = track(await start_server(ok_handler));
        const c = new DoHClient({ providers: [srv.url], timeout_ms: 2000 });
        const out = await c.query_raw(new Uint8Array(0));
        expect(Array.from(out)).toEqual(Array.from(STUB_RESPONSE));
    });

    test('unexpected content-type yields DoHUnexpectedContentTypeError', async () => {
        const srv = track(await start_server((_req, res) => {
            res.setHeader('Content-Type', 'text/plain');
            res.end('not dns');
        }));
        const c = new DoHClient({ providers: [srv.url], timeout_ms: 2000 });
        let err: unknown;
        try {
            await c.query('example.com.', TYPE_A);
        } catch (e) {
            err = e;
        }
        expect(err).toBeInstanceOf(DoHAllProvidersFailedError);
        expect((err as DoHAllProvidersFailedError).cause).toBeInstanceOf(DoHUnexpectedContentTypeError);
    });

    test('invalid qname propagates from build_query before any provider is hit', async () => {
        const srv = track(await start_server(ok_handler));
        const c = new DoHClient({ providers: [srv.url], timeout_ms: 2000 });
        const too_long = 'a'.repeat(70);
        await expect(c.query(`${too_long}.example.com.`, TYPE_A)).rejects.toThrow(/label too long/);
    });

    test('caller AbortSignal fails the query promptly', async () => {
        // Server holds the request open until the client gives up.
        const srv = track(await start_server((req, _res) => {
            // Never write; let the abort propagate.
            req.on('close', () => { /* connection closed by client */ });
        }));
        const c = new DoHClient({ providers: [srv.url], timeout_ms: 2000 });

        const controller = new AbortController();
        setTimeout(() => controller.abort(), 30);

        const start = Date.now();
        let err: unknown;
        try {
            await c.query('example.com.', TYPE_A, { signal: controller.signal });
        } catch (e) {
            err = e;
        }
        const elapsed = Date.now() - start;
        expect(err).toBeInstanceOf(DoHAllProvidersFailedError);
        expect((err as DoHAllProvidersFailedError).cause).toBeInstanceOf(DoHTransportError);
        expect(elapsed).toBeLessThan(500);
    });

    test('default_providers returns a fresh copy', () => {
        const a = default_providers();
        a[0] = 'https://example.invalid/dns-query';
        const b = default_providers();
        expect(b[0]).not.toBe(a[0]);
    });

    test('no providers configured raises DoHNoProvidersError', async () => {
        // Bypass the empty-list normalisation by reaching into the
        // private slot — matches the white-box test in
        // client_internal_test.go.
        const c = new DoHClient({ providers: ['https://dns.example.com/dns-query'], timeout_ms: 2000 });
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (c as any)._providers = [];
        await expect(c.query_raw(new Uint8Array([0x00]))).rejects.toBeInstanceOf(DoHNoProvidersError);
    });

    test('custom user_agent is sent on the request', async () => {
        let seen_ua = '';
        const srv = track(await start_server((req, res) => {
            seen_ua = String(req.headers['user-agent'] ?? '');
            res.setHeader('Content-Type', DOH_MEDIA_TYPE);
            res.end(Buffer.from(STUB_RESPONSE));
        }));
        const c = new DoHClient({ providers: [srv.url], user_agent: 'test-ua/1.0', timeout_ms: 2000 });
        await c.query('example.com.', TYPE_A);
        expect(seen_ua).toBe('test-ua/1.0');
    });
});
