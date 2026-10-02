// DNS-over-TLS client (RFC 7858). Ports dnsdata-go `resolver/dot`.
//
// Each query opens a TLS connection to a configured server, sends the
// query with the two-octet length framing of DNS over TCP (RFC 7858
// §3.3, ../stream.ts shared with the auth client), and reads one
// response. The server is authenticated as in the strict privacy
// profile of RFC 8310: its certificate must chain to a trusted root and
// match the server's name or address, and TLS is 1.2 or later.
// Connections are not reused across queries.

import * as net from 'net';
import * as tls from 'tls';
import { build_query_with_options, random_query_id, QueryOptions } from '../../wire/dns_wire';
import { normalize_host_port, parse_host_port } from '../addr';
import { to_response } from '../message';
import { ResolverResponse } from '../response';
import { SocketStream, StreamErrors, exchange } from '../stream';
import {
    DoTAbortedError,
    DoTAllServersFailedError,
    DoTIDMismatchError,
    DoTNoServersError,
    DoTResponseError,
    DoTResponseTooShortError,
    DoTTimeoutError,
    DoTTransportError,
} from './errors';

// The DNS-over-TLS port (RFC 7858 §3.1).
export const DOT_DEFAULT_PORT = 853;

// Per-server timeout (TLS dial, handshake, query and response), as in
// dnsdata-go.
export const DOT_DEFAULT_TIMEOUT_MS = 5000;

const HEADER_LENGTH = 12;
const MIN_TLS_VERSION = 'TLSv1.2';

// TLS settings the client passes on: a private CA to trust, and the
// name the certificate must match when it is not the host dialed.
export interface DoTTLSOptions {
    ca?: string | Buffer | Array<string | Buffer>;
    servername?: string;
}

export interface DoTClientOptions {
    // `host:port` (or a bare host, for port 853) to try in order.
    servers?: readonly string[];
    // Per-server timeout in milliseconds. Default 5000.
    timeout_ms?: number;
    tls?: DoTTLSOptions;
    // Sets the CD bit on every query (RFC 4035 §3.2.2). Default false.
    checking_disabled?: boolean;
}

export interface DoTQueryOptions {
    signal?: AbortSignal;
}

// The stream errors of this client.
const DOT_ERRORS: StreamErrors = {
    transport: (message, cause) => new DoTTransportError(message, cause),
    timeout: (operation, addr, timeout_ms) => new DoTTimeoutError(operation, addr, timeout_ms),
    aborted: () => new DoTAbortedError(),
};

// DoTClient speaks DNS over TLS. Nothing changes after construction, so
// concurrent queries on one client are safe.
export class DoTClient {
    private readonly _servers: readonly string[];
    private readonly _timeout_ms: number;
    private readonly _tls: DoTTLSOptions;
    private readonly _query_opts: QueryOptions;

    public constructor(opts: DoTClientOptions = {}) {
        this._servers = (opts.servers ?? []).map(normalize_dot_addr);
        this._timeout_ms = opts.timeout_ms ?? DOT_DEFAULT_TIMEOUT_MS;
        this._tls = { ...opts.tls };
        this._query_opts = { checking_disabled: opts.checking_disabled ?? false };
    }

    // A fresh copy of the configured server list.
    public servers(): string[] {
        return [...this._servers];
    }

    // Sends a query for (qname, qtype) and returns the raw response from
    // the first server that answers.
    public async query(qname: string, qtype: number, opts: DoTQueryOptions = {}): Promise<Uint8Array> {
        const id = random_query_id();
        return this.query_raw(id, build_query_with_options(id, qname, qtype, this._query_opts), opts);
    }

    // Sends a prebuilt query whose transaction ID is query_id. Servers
    // are tried in order; when all fail, DoTAllServersFailedError carries
    // the first failure as `.cause`.
    public async query_raw(query_id: number, query: Uint8Array, opts: DoTQueryOptions = {}): Promise<Uint8Array> {
        if (this._servers.length === 0) throw new DoTNoServersError();
        let first_err: unknown = null;
        for (const addr of this._servers) {
            try {
                return await this.query_one(addr, query_id, query, opts.signal);
            } catch (err) {
                if (first_err === null) first_err = err;
            }
        }
        throw new DoTAllServersFailedError(first_err);
    }

    // Runs a query and returns the answer and authority records with the
    // AD bit and RCODE; matches verifier.Resolver.query. A non-zero RCODE
    // is data; a response that does not parse is DoTResponseError.
    public async resolve(name: string, qtype: number, signal?: AbortSignal): Promise<ResolverResponse> {
        const raw = await this.query(name, qtype, { signal });
        return to_response(raw, (step, message) => new DoTResponseError(`${step}: ${message}`));
    }

    private async query_one(addr: string, query_id: number, query: Uint8Array, signal?: AbortSignal): Promise<Uint8Array> {
        const socket = await connect(addr, this._tls, this._timeout_ms, signal);
        const conn = new SocketStream(socket, addr, { timeout_ms: this._timeout_ms, signal }, DOT_ERRORS);
        try {
            const resp = await exchange(conn, query);
            check_reply(resp, query_id);
            return resp;
        } finally {
            conn.close();
        }
    }
}

// connect opens a TLS connection to addr and completes the handshake,
// authenticating the server: its certificate must chain to a trusted
// root (tls_opts.ca, or Node's roots) and match tls_opts.servername or
// the host dialed.
function connect(addr: string, tls_opts: DoTTLSOptions, timeout_ms: number, signal?: AbortSignal): Promise<tls.TLSSocket> {
    return new Promise((resolve, reject) => {
        if (signal?.aborted) {
            reject(new DoTAbortedError());
            return;
        }
        let host: string;
        let port: number;
        try {
            ({ host, port } = parse_host_port(addr));
        } catch (err) {
            reject(new DoTTransportError(`dial ${addr}`, err));
            return;
        }
        const socket = tls.connect({
            host,
            port,
            ca: tls_opts.ca,
            // SNI takes a name, never an address (RFC 6066 §3).
            servername: tls_opts.servername ?? (net.isIP(host) === 0 ? host : undefined),
            minVersion: MIN_TLS_VERSION,
            rejectUnauthorized: true,
        });
        const fail = (err: Error): void => {
            clearTimeout(timer);
            signal?.removeEventListener('abort', on_abort);
            socket.destroy();
            reject(err);
        };
        const timer = setTimeout(() => fail(new DoTTimeoutError('dial', addr, timeout_ms)), timeout_ms);
        const on_abort = (): void => fail(new DoTAbortedError());
        signal?.addEventListener('abort', on_abort, { once: true });
        socket.once('error', (err: Error) => fail(new DoTTransportError(`dial ${addr}`, err)));
        socket.once('secureConnect', () => {
            clearTimeout(timer);
            signal?.removeEventListener('abort', on_abort);
            resolve(socket);
        });
    });
}

// check_reply asserts a full header and the query's transaction ID.
function check_reply(resp: Uint8Array, query_id: number): void {
    if (resp.length < HEADER_LENGTH) throw new DoTResponseTooShortError(resp.length);
    const resp_id = (resp[0] << 8) | resp[1];
    if (resp_id !== query_id) throw new DoTIDMismatchError(resp_id, query_id);
}

// normalize_dot_addr returns addr with port 853 when it has none; a bare
// IPv6 address is bracketed. Ports dnsdata-go `dot.NormalizeAddr`.
export function normalize_dot_addr(addr: string): string {
    return normalize_host_port(addr, DOT_DEFAULT_PORT);
}
