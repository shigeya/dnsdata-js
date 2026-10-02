// DNS messages on a byte stream: a two-octet length in front of each
// message (RFC 1035 §4.2.2), for TCP (RFC 7766 §8) and for TLS
// (RFC 7858 §3.3). The auth and DoT clients share it. Ports dnsdata-go
// `resolver/internal/stream`; SocketStream is the Node socket reader
// both clients wrap a connected socket in.

import * as net from 'net';

const PREFIX_LENGTH = 2;
const MAX_MESSAGE_LENGTH = 0xffff;

// StreamConnection is a connected byte stream. recv_exact reads exactly
// n octets, rejecting if the stream ends first.
export interface StreamConnection {
    send(data: Uint8Array): Promise<void>;
    recv_exact(n: number): Promise<Uint8Array>;
    close(): void;
}

// StreamErrors makes the errors a SocketStream raises, so each client
// keeps its own error classes and messages.
export interface StreamErrors {
    // A socket failure; message names the step and the address.
    transport(message: string, cause: unknown): Error;
    timeout(operation: string, addr: string, timeout_ms: number): Error;
    aborted(): Error;
}

// exchange writes query behind its length prefix in a single write
// (RFC 7766 §8) and reads one length-prefixed message back.
export async function exchange(conn: StreamConnection, query: Uint8Array): Promise<Uint8Array> {
    if (query.length > MAX_MESSAGE_LENGTH) {
        throw new RangeError(`query of ${query.length} octets exceeds ${MAX_MESSAGE_LENGTH}`);
    }
    const out = new Uint8Array(PREFIX_LENGTH + query.length);
    out[0] = (query.length >> 8) & 0xff;
    out[1] = query.length & 0xff;
    out.set(query, PREFIX_LENGTH);
    await conn.send(out);
    const hdr = await conn.recv_exact(PREFIX_LENGTH);
    return conn.recv_exact((hdr[0] << 8) | hdr[1]);
}

interface PendingRead {
    n: number;
    resolve: (buf: Uint8Array) => void;
    reject: (err: unknown) => void;
    timer: NodeJS.Timeout;
    on_abort?: () => void;
}

// SocketStream reads and writes a connected Node socket (net.Socket or
// tls.TLSSocket), buffering what arrives until a read can be served.
// Each read has its own timeout and honours the signal.
export class SocketStream implements StreamConnection {
    private readonly chunks: Buffer[] = [];
    private buffered_len = 0;
    private pending: PendingRead | null = null;
    private fatal: unknown = null;
    private ended = false;
    private closed = false;

    constructor(
        private readonly socket: net.Socket,
        private readonly addr: string,
        private readonly opts: { timeout_ms: number; signal?: AbortSignal },
        private readonly errors: StreamErrors,
    ) {
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
            this.fatal = errors.transport(addr, err);
            this.try_resolve_pending();
        });
        socket.on('close', () => {
            this.ended = true;
            this.try_resolve_pending();
        });
    }

    send(data: Uint8Array): Promise<void> {
        return new Promise((resolve, reject) => {
            // Copy, so the caller may reuse data once send resolves.
            this.socket.write(Buffer.from(data), (err) => {
                if (err) {
                    reject(this.errors.transport(`write ${this.addr}`, err));
                    return;
                }
                resolve();
            });
        });
    }

    recv_exact(n: number): Promise<Uint8Array> {
        const signal = this.opts.signal;
        return new Promise((resolve, reject) => {
            if (this.fatal !== null) {
                reject(this.fatal);
                return;
            }
            if (signal?.aborted) {
                reject(this.errors.aborted());
                return;
            }
            const timer = setTimeout(() => {
                this.pending = null;
                reject(this.errors.timeout('read', this.addr, this.opts.timeout_ms));
            }, this.opts.timeout_ms);
            const on_abort = (): void => {
                clearTimeout(timer);
                this.pending = null;
                reject(this.errors.aborted());
            };
            signal?.addEventListener('abort', on_abort, { once: true });
            this.pending = { n, resolve, reject, timer, on_abort: signal ? on_abort : undefined };
            this.try_resolve_pending();
        });
    }

    close(): void {
        if (this.closed) return;
        this.closed = true;
        this.socket.destroy();
    }

    private settle(p: PendingRead): void {
        this.pending = null;
        clearTimeout(p.timer);
        if (p.on_abort) this.opts.signal?.removeEventListener('abort', p.on_abort);
    }

    private try_resolve_pending(): void {
        const p = this.pending;
        if (p === null) return;
        if (this.fatal !== null) {
            this.settle(p);
            p.reject(this.fatal);
            return;
        }
        if (this.buffered_len >= p.n) {
            this.settle(p);
            p.resolve(this.take(p.n));
            return;
        }
        if (this.ended) {
            this.settle(p);
            p.reject(this.errors.transport(`read ${this.addr}`,
                new Error(`stream ended after ${this.buffered_len} of ${p.n} bytes`)));
        }
    }

    // take removes the first n buffered octets.
    private take(n: number): Uint8Array {
        const out = new Uint8Array(n);
        let written = 0;
        while (written < n) {
            const head = this.chunks[0];
            const count = Math.min(head.length, n - written);
            out.set(head.subarray(0, count), written);
            written += count;
            if (count === head.length) {
                this.chunks.shift();
            } else {
                this.chunks[0] = head.subarray(count);
            }
        }
        this.buffered_len -= n;
        return out;
    }
}
