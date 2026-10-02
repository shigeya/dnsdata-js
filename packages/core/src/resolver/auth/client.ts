// Plain DNS over UDP / TCP client for use against authoritative name
// servers, recursive resolvers, or a local stub. Mirrors the
// dnsdata-go `resolver/auth` package (UP-003 / shigeya/dnsdata-js#7).
//
// Transport behaviour:
//   - Queries are built with build_query / build_query_with_id from
//     wire/dns_wire (shared EDNS(0) / DO-bit shape with DoH).
//   - UDP is tried first. If the response has the TC (truncation) flag
//     set, the same query is replayed on TCP per RFC 1035 §4.2.1.
//   - TCP frames are prefixed with a 2-byte big-endian length per
//     RFC 1035 §4.2.2 (../stream.ts, shared with the DoT client).
//   - Per DESIGN.md MUST 9 (carried over from dnsdata-go), the caller
//     supplies the server list. Nothing is read from /etc/resolv.conf,
//     no filesystem touches.
//
// Multi-server failover is identical in shape to dnsdata-go's
// resolver/doh: the configured servers are tried in order; the first
// one that returns a usable response wins.
//
// Node-specific dgram / net socket wrappers (NodeDialer,
// NodeUdpConnection) live in this file by design: REFACTOR_PLAN.md §3
// P7 calls out that Go has no equivalent so keeping them as a separate
// file would not yield a 1:1 mapping. The TCP reader is the shared
// SocketStream of ../stream.ts, which the DoT client also uses.

import * as dgram from 'dgram';
import * as net from 'net';
import { build_query_with_options, random_query_id, QueryOptions } from '../../wire/dns_wire';
import { normalize_host_port, parse_host_port } from '../addr';
import { SocketStream, StreamErrors, exchange } from '../stream';
import {
    AuthAbortedError,
    AuthAllServersFailedError,
    AuthIDMismatchError,
    AuthNoServersError,
    AuthResolverError,
    AuthResponseTooShortError,
    AuthTimeoutError,
    AuthTransportError,
    AuthUDPTruncatedError,
    error_message,
} from './errors';

// DNS over UDP / TCP port (RFC 1035 §4.2).
const AUTH_DEFAULT_PORT = 53;

//////////////////////////////////////////////////////////////////// Dialer

// UdpConnection is the abstract one-shot UDP request channel. The
// auth client opens it, writes the query once, reads exactly one
// datagram, then closes. Implementations MUST resolve recv() with
// the first received datagram and reject pending operations on
// close() / timeout / signal abort.
export interface UdpConnection {
    send(data: Uint8Array): Promise<void>;
    recv(): Promise<Uint8Array>;
    close(): void;
}

// TcpConnection is the abstract TCP byte stream. recv_exact reads
// exactly n bytes, rejecting if the stream ends first.
export interface TcpConnection {
    send(data: Uint8Array): Promise<void>;
    recv_exact(n: number): Promise<Uint8Array>;
    close(): void;
}

// DialOptions carries the per-attempt timeout and optional abort
// signal supplied by the caller.
export interface DialOptions {
    timeout_ms: number;
    signal?: AbortSignal;
}

// Dialer abstracts transport construction so tests can swap in fake
// network sockets. Implementations should honour both the timeout
// (single-attempt budget) and the signal (caller-cancellation).
export interface Dialer {
    dial_udp(addr: string, opts: DialOptions): Promise<UdpConnection>;
    dial_tcp(addr: string, opts: DialOptions): Promise<TcpConnection>;
}

//////////////////////////////////////////////////////////////////// NodeDialer

// NodeDialer is the production [Dialer] backed by Node.js's `dgram`
// and `net` modules. Constructed by [AuthClient] when no dialer is
// supplied; not exported because callers should use the public
// AuthClient API.
class NodeDialer implements Dialer {
    async dial_udp(addr: string, opts: DialOptions): Promise<UdpConnection> {
        const { host, port } = parse_addr(addr);
        const family = is_ipv6(host) ? 'udp6' : 'udp4';
        const socket = dgram.createSocket(family);
        return new NodeUdpConnection(socket, host, port, opts);
    }

    async dial_tcp(addr: string, opts: DialOptions): Promise<TcpConnection> {
        const { host, port } = parse_addr(addr);
        return new Promise((resolve, reject) => {
            const socket = net.createConnection({ host, port });
            const timer = setTimeout(() => {
                socket.destroy();
                reject(new AuthTimeoutError('tcp dial', addr, opts.timeout_ms));
            }, opts.timeout_ms);
            const on_abort = () => {
                clearTimeout(timer);
                socket.destroy();
                reject(new AuthAbortedError());
            };
            if (opts.signal) {
                if (opts.signal.aborted) {
                    clearTimeout(timer);
                    socket.destroy();
                    reject(new AuthAbortedError());
                    return;
                }
                opts.signal.addEventListener('abort', on_abort, { once: true });
            }
            socket.once('connect', () => {
                clearTimeout(timer);
                if (opts.signal) opts.signal.removeEventListener('abort', on_abort);
                resolve(new SocketStream(socket, addr, opts, TCP_ERRORS));
            });
            socket.once('error', (err: Error) => {
                clearTimeout(timer);
                if (opts.signal) opts.signal.removeEventListener('abort', on_abort);
                reject(new AuthTransportError(`tcp dial ${addr}`, err));
            });
        });
    }
}

class NodeUdpConnection implements UdpConnection {
    private readonly socket: dgram.Socket;
    private readonly host: string;
    private readonly port: number;
    private readonly addr: string;
    private readonly timeout_ms: number;
    private readonly signal?: AbortSignal;
    private closed = false;

    constructor(socket: dgram.Socket, host: string, port: number, opts: DialOptions) {
        this.socket = socket;
        this.host = host;
        this.port = port;
        this.addr = `${host}:${port}`;
        this.timeout_ms = opts.timeout_ms;
        this.signal = opts.signal;
    }

    send(data: Uint8Array): Promise<void> {
        return new Promise((resolve, reject) => {
            this.socket.send(data, 0, data.length, this.port, this.host, (err) => {
                if (err) {
                    reject(new AuthTransportError(`udp write ${this.addr}`, err));
                    return;
                }
                resolve();
            });
        });
    }

    recv(): Promise<Uint8Array> {
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this.cleanup();
                reject(new AuthTimeoutError('udp read', this.addr, this.timeout_ms));
            }, this.timeout_ms);
            const on_abort = () => {
                clearTimeout(timer);
                this.cleanup();
                reject(new AuthAbortedError());
            };
            const on_message = (data: Buffer) => {
                clearTimeout(timer);
                if (this.signal) this.signal.removeEventListener('abort', on_abort);
                // Copy out of Buffer's pooled allocation.
                resolve(new Uint8Array(data));
            };
            const on_error = (err: Error) => {
                clearTimeout(timer);
                if (this.signal) this.signal.removeEventListener('abort', on_abort);
                reject(new AuthTransportError(`udp read ${this.addr}`, err));
            };
            this.socket.once('message', on_message);
            this.socket.once('error', on_error);
            if (this.signal) {
                if (this.signal.aborted) {
                    clearTimeout(timer);
                    this.cleanup();
                    reject(new AuthAbortedError());
                    return;
                }
                this.signal.addEventListener('abort', on_abort, { once: true });
            }
        });
    }

    close(): void {
        this.cleanup();
    }

    private cleanup(): void {
        if (this.closed) return;
        this.closed = true;
        try {
            this.socket.close();
        } catch {
            // dgram already closed — ignore.
        }
    }
}

// TCP_ERRORS makes the shared SocketStream raise this client's errors,
// with the messages it always had ("tcp read <addr>", ...).
const TCP_ERRORS: StreamErrors = {
    transport: (message, cause) => new AuthTransportError(`tcp ${message}`, cause),
    timeout: (operation, addr, timeout_ms) => new AuthTimeoutError(`tcp ${operation}`, addr, timeout_ms),
    aborted: () => new AuthAbortedError(),
};

//////////////////////////////////////////////////////////////////// Client

// Default per-server per-transport timeout (5s) matches dnsdata-go.
export const AUTH_DEFAULT_TIMEOUT_MS = 5000;

// Default UDP receive buffer, also the EDNS payload size advertised
// by build_query.
export const AUTH_DEFAULT_UDP_BUFFER_SIZE = 4096;

// RFC 1035 minimum DNS UDP message size — any caller-supplied smaller
// value is clamped up to this.
export const AUTH_MIN_UDP_BUFFER_SIZE = 512;

export interface AuthClientOptions {
    // List of `ip:port` (or bare `ip`) strings to try in order.
    // Bare addresses get :53 appended by normalize_addr.
    servers?: readonly string[];

    // Per-server per-transport timeout in milliseconds. Default 5000.
    timeout_ms?: number;

    // UDP receive buffer. Values below 512 are clamped up to 512.
    udp_buffer_size?: number;

    // Dialer for tests; defaults to the Node.js dgram/net-backed
    // implementation.
    dialer?: Dialer;

    // Sets the CD bit on every query (RFC 4035 §3.2.2), so a validating
    // server returns data it would reject as bogus instead of SERVFAIL.
    // Default false. Mirrors dnsdata-go `auth.WithCheckingDisabled`.
    checking_disabled?: boolean;
}

export interface AuthQueryOptions {
    // Caller-supplied cancellation. Honoured for both UDP and TCP
    // attempts; surfaces as AuthAbortedError.
    signal?: AbortSignal;
}

// AuthClient speaks plain DNS over UDP / TCP. Construct with options;
// all fields are immutable after construction so concurrent calls
// against a single client are safe.
//
// Ports the dnsdata-go `auth.Client` type (UP-003).
//
// The `resolve` method that lifts a wire response into
// ResourceRecord[] is installed via TypeScript declaration merging
// from ./resolve — importing the auth/index.ts barrel (or
// resolver_auth.ts back-compat shim) guarantees the method exists.
export class AuthClient {
    private readonly _servers: readonly string[];
    private readonly _timeout_ms: number;
    private readonly _udp_buffer_size: number;
    private readonly _dialer: Dialer;
    private readonly _query_opts: QueryOptions;

    public constructor(opts: AuthClientOptions = {}) {
        this._query_opts = { checking_disabled: opts.checking_disabled ?? false };
        const raw_servers = opts.servers ?? [];
        this._servers = raw_servers.map(normalize_addr);
        this._timeout_ms = opts.timeout_ms ?? AUTH_DEFAULT_TIMEOUT_MS;
        const buf = opts.udp_buffer_size ?? AUTH_DEFAULT_UDP_BUFFER_SIZE;
        this._udp_buffer_size = buf < AUTH_MIN_UDP_BUFFER_SIZE ? AUTH_MIN_UDP_BUFFER_SIZE : buf;
        this._dialer = opts.dialer ?? new NodeDialer();
    }

    // Fresh copy of the configured server list. Mutation of the
    // returned array does not affect the client.
    public servers(): string[] {
        return [...this._servers];
    }

    // Issue a DNS query for (qname, qtype) and return the raw response
    // message bytes from the first server that succeeds. The caller
    // is responsible for parsing the response (see parse_message).
    //
    // Throws AuthNoServersError if no servers are configured, and
    // AuthAllServersFailedError if every server failed.
    public async query(qname: string, qtype: number, opts: AuthQueryOptions = {}): Promise<Uint8Array> {
        const id = random_query_id();
        const msg = build_query_with_options(id, qname, qtype, this._query_opts);
        return this.query_raw(id, msg, opts);
    }

    // Send a prebuilt DNS query message and return the response
    // bytes. The caller supplies the transaction ID separately so
    // the client can verify the response is a reply to this query.
    public async query_raw(query_id: number, query: Uint8Array, opts: AuthQueryOptions = {}): Promise<Uint8Array> {
        if (this._servers.length === 0) throw new AuthNoServersError();
        let first_err: unknown = null;
        for (const addr of this._servers) {
            try {
                return await this._query_one(addr, query_id, query, opts.signal);
            } catch (err) {
                if (first_err === null) first_err = err;
                // Try next server.
            }
        }
        throw new AuthAllServersFailedError(first_err);
    }

    private async _query_one(addr: string, query_id: number, query: Uint8Array, signal?: AbortSignal): Promise<Uint8Array> {
        try {
            return await this._query_udp(addr, query_id, query, signal);
        } catch (err) {
            if (err instanceof AuthUDPTruncatedError) {
                return this._query_tcp(addr, query_id, query, signal);
            }
            throw err;
        }
    }

    private async _query_udp(addr: string, query_id: number, query: Uint8Array, signal?: AbortSignal): Promise<Uint8Array> {
        const conn = await this._dialer.dial_udp(addr, { timeout_ms: this._timeout_ms, signal });
        try {
            await conn.send(query);
            const resp = await conn.recv();
            validate_response(resp, query_id);
            if (resp.length >= 4 && (resp[2] & 0x02) !== 0) {
                throw new AuthUDPTruncatedError();
            }
            return resp;
        } finally {
            conn.close();
        }
    }

    private async _query_tcp(addr: string, query_id: number, query: Uint8Array, signal?: AbortSignal): Promise<Uint8Array> {
        const conn = await this._dialer.dial_tcp(addr, { timeout_ms: this._timeout_ms, signal });
        try {
            const resp = await exchange(conn, query);
            validate_response(resp, query_id);
            return resp;
        } finally {
            conn.close();
        }
    }
}

function validate_response(resp: Uint8Array, query_id: number): void {
    if (resp.length < 12) throw new AuthResponseTooShortError(resp.length);
    const resp_id = (resp[0] << 8) | resp[1];
    if (resp_id !== query_id) throw new AuthIDMismatchError(resp_id, query_id);
}

//////////////////////////////////////////////////////////// NormalizeAddr

// normalize_addr ensures addr has a port suffix, defaulting to 53.
// IPv6 literals must already include brackets when supplied with a
// port (e.g. `[::1]:53`). Bare IPv6 without brackets is wrapped
// automatically: `::1` → `[::1]:53`.
//
// Ports dnsdata-go `auth.NormalizeAddr`.
export function normalize_addr(addr: string): string {
    return normalize_host_port(addr, AUTH_DEFAULT_PORT);
}

// parse_addr splits a normalized address into host + port (../addr.ts),
// as AuthResolverError when it is malformed.
function parse_addr(addr: string): { host: string; port: number } {
    try {
        return parse_host_port(addr);
    } catch (err) {
        throw new AuthResolverError(error_message(err));
    }
}

function is_ipv6(host: string): boolean {
    return host.includes(':');
}
