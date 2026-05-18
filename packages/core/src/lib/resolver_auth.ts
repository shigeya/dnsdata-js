// Plain DNS over UDP / TCP client for use against authoritative name
// servers, recursive resolvers, or a local stub. Mirrors the
// dnsdata-go `resolver/auth` package (UP-003 / shigeya/dnsdata-js#7).
//
// Transport behaviour:
//   - Queries are built with build_query / build_query_with_id from
//     dns_wire (shared EDNS(0) / DO-bit shape with future DoH).
//   - UDP is tried first. If the response has the TC (truncation) flag
//     set, the same query is replayed on TCP per RFC 1035 §4.2.1.
//   - TCP frames are prefixed with a 2-byte big-endian length per
//     RFC 1035 §4.2.2.
//   - Per DESIGN.md MUST 9 (carried over from dnsdata-go), the caller
//     supplies the server list. Nothing is read from /etc/resolv.conf,
//     no filesystem touches.
//
// Multi-server failover is identical in shape to dnsdata-go's
// resolver/doh: the configured servers are tried in order; the first
// one that returns a usable response wins.

import * as dgram from 'dgram';
import * as net from 'net';
import { build_query_with_id, random_query_id } from '../wire/dns_wire';
import { parse_message, RawRR } from '../wire/dns_message';
import { rdata_to_string } from '../wire/rdata_decoder';
import { ResourceRecord, ns_type, ns_class } from './dns_zone';
import { RRTypeToString, RRClassToString } from '../types/dns_type_table';

//////////////////////////////////////////////////////////////////// Errors

// AuthResolverError is the umbrella class for every failure returned
// by [AuthClient]. Callers can route through one `instanceof` check
// while discriminating by subclass when they care.
export class AuthResolverError extends Error {
    public constructor(message: string) {
        super(message);
        this.name = 'AuthResolverError';
    }
}

// Returned when the configured server list is empty.
export class AuthNoServersError extends AuthResolverError {
    public constructor() {
        super('auth: no servers configured');
        this.name = 'AuthNoServersError';
    }
}

// Returned when every configured server errored. The first inner
// error is preserved on `.cause` so callers can still discriminate
// via the underlying type.
export class AuthAllServersFailedError extends AuthResolverError {
    public readonly cause: unknown;
    public constructor(cause: unknown) {
        super(`auth: all servers failed: ${error_message(cause)}`);
        this.name = 'AuthAllServersFailedError';
        this.cause = cause;
    }
}

// Internal-but-exported sentinel: thrown by the UDP path when the
// response has the TC flag set; the [AuthClient] catches and retries
// on TCP. Users calling the lower-level helpers can still observe it.
export class AuthUDPTruncatedError extends AuthResolverError {
    public constructor() {
        super('auth: udp response truncated, retry on tcp');
        this.name = 'AuthUDPTruncatedError';
    }
}

// Returned when the server sent fewer than the 12-byte DNS header.
export class AuthResponseTooShortError extends AuthResolverError {
    public constructor(length: number) {
        super(`auth: response too short: ${length} bytes`);
        this.name = 'AuthResponseTooShortError';
    }
}

// Returned when the response's transaction ID doesn't match the
// query's. Mitigates Kaminsky-style off-path poisoning attempts
// within a single query / response pairing.
export class AuthIDMismatchError extends AuthResolverError {
    public constructor(response_id: number, query_id: number) {
        super(
            `auth: response transaction ID mismatch: response 0x${response_id.toString(16).padStart(4, '0')}, query 0x${query_id.toString(16).padStart(4, '0')}`,
        );
        this.name = 'AuthIDMismatchError';
    }
}

// Returned when the DNS response itself is malformed or carries a
// non-zero RCODE. Distinguishes "response says no" from transport
// failures.
export class AuthResponseError extends AuthResolverError {
    public constructor(message: string) {
        super(`auth: bad response: ${message}`);
        this.name = 'AuthResponseError';
    }
}

// Returned on transport-level failures (dial, write, read, timeout).
export class AuthTransportError extends AuthResolverError {
    public readonly cause: unknown;
    public constructor(message: string, cause: unknown) {
        super(`auth: ${message}: ${error_message(cause)}`);
        this.name = 'AuthTransportError';
        this.cause = cause;
    }
}

// Returned when a transport attempt did not finish before the
// per-server timeout elapsed.
export class AuthTimeoutError extends AuthResolverError {
    public constructor(transport: string, addr: string, timeout_ms: number) {
        super(`auth: ${transport} ${addr} timed out after ${timeout_ms}ms`);
        this.name = 'AuthTimeoutError';
    }
}

// Returned when the caller's AbortSignal fired before the query
// completed.
export class AuthAbortedError extends AuthResolverError {
    public constructor() {
        super('auth: aborted by caller');
        this.name = 'AuthAbortedError';
    }
}

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
                resolve(new NodeTcpConnection(socket, addr, opts));
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

class NodeTcpConnection implements TcpConnection {
    private readonly socket: net.Socket;
    private readonly addr: string;
    private readonly timeout_ms: number;
    private readonly signal?: AbortSignal;
    private readonly chunks: Buffer[] = [];
    private buffered_len = 0;
    private pending: { n: number; resolve: (buf: Uint8Array) => void; reject: (err: unknown) => void; timer: NodeJS.Timeout; on_abort?: () => void } | null = null;
    private fatal: unknown = null;
    private ended = false;
    private closed = false;

    constructor(socket: net.Socket, addr: string, opts: DialOptions) {
        this.socket = socket;
        this.addr = addr;
        this.timeout_ms = opts.timeout_ms;
        this.signal = opts.signal;

        socket.on('data', (data: Buffer) => {
            this.chunks.push(data);
            this.buffered_len += data.length;
            this.try_resolve_pending();
        });
        socket.on('end', () => {
            this.ended = true;
            this.try_resolve_pending();
        });
        socket.on('error', (err: Error) => {
            this.fatal = new AuthTransportError(`tcp ${this.addr}`, err);
            this.try_resolve_pending();
        });
        socket.on('close', () => {
            this.ended = true;
            this.try_resolve_pending();
        });
    }

    send(data: Uint8Array): Promise<void> {
        return new Promise((resolve, reject) => {
            // Node accepts Uint8Array via Buffer.from without copy on
            // identical backing ArrayBuffer, but to keep semantics
            // predictable we copy explicitly.
            this.socket.write(Buffer.from(data), (err) => {
                if (err) {
                    reject(new AuthTransportError(`tcp write ${this.addr}`, err));
                    return;
                }
                resolve();
            });
        });
    }

    recv_exact(n: number): Promise<Uint8Array> {
        return new Promise((resolve, reject) => {
            if (this.fatal !== null) {
                reject(this.fatal);
                return;
            }
            if (this.signal && this.signal.aborted) {
                reject(new AuthAbortedError());
                return;
            }
            const timer = setTimeout(() => {
                this.pending = null;
                reject(new AuthTimeoutError('tcp read', this.addr, this.timeout_ms));
            }, this.timeout_ms);
            const on_abort = () => {
                clearTimeout(timer);
                this.pending = null;
                reject(new AuthAbortedError());
            };
            if (this.signal) {
                this.signal.addEventListener('abort', on_abort, { once: true });
            }
            this.pending = { n, resolve, reject, timer, on_abort: this.signal ? on_abort : undefined };
            this.try_resolve_pending();
        });
    }

    close(): void {
        if (this.closed) return;
        this.closed = true;
        try {
            this.socket.destroy();
        } catch {
            // already destroyed — ignore.
        }
    }

    private try_resolve_pending(): void {
        const p = this.pending;
        if (p === null) return;
        if (this.fatal !== null) {
            this.pending = null;
            clearTimeout(p.timer);
            if (p.on_abort && this.signal) this.signal.removeEventListener('abort', p.on_abort);
            p.reject(this.fatal);
            return;
        }
        if (this.buffered_len >= p.n) {
            const out = new Uint8Array(p.n);
            let written = 0;
            while (written < p.n) {
                const head = this.chunks[0];
                const take = Math.min(head.length, p.n - written);
                out.set(head.subarray(0, take), written);
                written += take;
                if (take === head.length) {
                    this.chunks.shift();
                } else {
                    this.chunks[0] = head.subarray(take);
                }
            }
            this.buffered_len -= p.n;
            this.pending = null;
            clearTimeout(p.timer);
            if (p.on_abort && this.signal) this.signal.removeEventListener('abort', p.on_abort);
            p.resolve(out);
            return;
        }
        if (this.ended) {
            this.pending = null;
            clearTimeout(p.timer);
            if (p.on_abort && this.signal) this.signal.removeEventListener('abort', p.on_abort);
            p.reject(new AuthTransportError(`tcp read ${this.addr}`, new Error(`stream ended after ${this.buffered_len} of ${p.n} bytes`)));
            return;
        }
    }
}

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
export class AuthClient {
    private readonly _servers: readonly string[];
    private readonly _timeout_ms: number;
    private readonly _udp_buffer_size: number;
    private readonly _dialer: Dialer;

    public constructor(opts: AuthClientOptions = {}) {
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
        const msg = build_query_with_id(id, qname, qtype);
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

    // Run a DNS query, parse the response, and return its answer +
    // authority section records as presentation-form ResourceRecord
    // values. Both sections are included so a verifier can locate
    // NSEC / NSEC3 negative proofs (RFC 4035 §3.1.3 places those in
    // the authority section).
    //
    // The signature matches verifier.Resolver.query so an AuthClient
    // method-bound reference (or thin wrapper) can be passed directly:
    //
    //   const client = new AuthClient({ servers: ['1.1.1.1'] });
    //   const v = new Verifier({ resolver: { query: client.resolve.bind(client) } });
    public async resolve(name: string, qtype: number, signal?: AbortSignal): Promise<ResourceRecord[]> {
        const raw = await this.query(name, qtype, { signal });
        let msg;
        try {
            msg = parse_message(raw);
        } catch (err) {
            throw new AuthResponseError(`parse: ${error_message(err)}`);
        }
        const rcode = msg.header.rcode();
        if (rcode !== 0) {
            throw new AuthResponseError(`RCODE=${rcode}`);
        }
        const out: ResourceRecord[] = [];
        for (const rr of msg.answer) out.push(this._raw_to_record(msg.raw, rr));
        for (const rr of msg.authority) out.push(this._raw_to_record(msg.raw, rr));
        return out;
    }

    private _raw_to_record(raw: Uint8Array, rr: RawRR): ResourceRecord {
        let value: string;
        try {
            value = rdata_to_string(raw, rr.type, rr.rdata, rr.rdataStart);
        } catch (err) {
            throw new AuthResponseError(`rdata decode: ${error_message(err)}`);
        }
        try {
            const type_name = RRTypeToString(rr.type as ns_type);
            const class_name = RRClassToString(rr.class as ns_class);
            return new ResourceRecord(rr.name, rr.ttl, class_name, type_name, value);
        } catch (err) {
            throw new AuthResponseError(`construct record: ${error_message(err)}`);
        }
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
            // 2-byte big-endian length prefix.
            const prefix = new Uint8Array(2);
            prefix[0] = (query.length >> 8) & 0xFF;
            prefix[1] = query.length & 0xFF;
            await conn.send(prefix);
            await conn.send(query);

            const hdr = await conn.recv_exact(2);
            const resp_len = (hdr[0] << 8) | hdr[1];
            const resp = await conn.recv_exact(resp_len);
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
    if (has_port(addr)) return addr;
    return join_host_port(addr, 53);
}

// has_port returns true when addr already carries a port suffix.
// Mirrors Go's net.SplitHostPort succeed-or-fail outcome for the
// shapes we accept: "host:port", "[ipv6]:port", "ipv4:port".
function has_port(addr: string): boolean {
    if (addr.startsWith('[')) {
        // "[ipv6]:port" — bracket form. Require closing bracket and ':'.
        const close = addr.indexOf(']');
        if (close < 0) return false;
        return close + 1 < addr.length && addr[close + 1] === ':';
    }
    // Bare host:port. If the host contains more than one ':' it's a
    // bare IPv6 address (e.g. "::1") — that's NOT host:port.
    const colon = addr.indexOf(':');
    if (colon < 0) return false;
    const last = addr.lastIndexOf(':');
    return colon === last;
}

function join_host_port(host: string, port: number | string): string {
    const p = String(port);
    if (host.includes(':') && !host.startsWith('[')) {
        return `[${host}]:${p}`;
    }
    return `${host}:${p}`;
}

// parse_addr splits a normalized address into host + port. The
// returned host is the bare IP / hostname (no IPv6 brackets) — this
// is what Node's net / dgram APIs expect.
function parse_addr(addr: string): { host: string; port: number } {
    if (addr.startsWith('[')) {
        const close = addr.indexOf(']');
        if (close < 0 || close + 1 >= addr.length || addr[close + 1] !== ':') {
            throw new AuthResolverError(`invalid bracketed address: ${addr}`);
        }
        const host = addr.slice(1, close);
        const port = Number(addr.slice(close + 2));
        if (!Number.isFinite(port) || port < 0 || port > 65535) {
            throw new AuthResolverError(`invalid port in address: ${addr}`);
        }
        return { host, port };
    }
    const last = addr.lastIndexOf(':');
    if (last < 0) {
        throw new AuthResolverError(`missing port in address: ${addr}`);
    }
    const host = addr.slice(0, last);
    const port = Number(addr.slice(last + 1));
    if (!Number.isFinite(port) || port < 0 || port > 65535) {
        throw new AuthResolverError(`invalid port in address: ${addr}`);
    }
    return { host, port };
}

function is_ipv6(host: string): boolean {
    return host.includes(':');
}

function error_message(err: unknown): string {
    if (err instanceof Error) return err.message;
    return String(err);
}
