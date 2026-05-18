// DNS-over-HTTPS client per RFC 8484.
//
// Ports the dnsdata-go `resolver/doh/client.go` module (originated in
// dnsdata-go v0.1.0; tracked here as UP-007).
//
// The client speaks the application/dns-message wire format, picks
// providers in caller-supplied order with automatic failover on
// transport errors or non-2xx responses, and reuses the EDNS(0)/DO
// query builder from dns_wire so that DoH and plain UDP/TCP DNS share
// the same query shape.
//
// Default providers (Google → Cloudflare → Quad9) are exposed as
// constants and are used when [DoHClient] is constructed without an
// explicit providers list.
//
// Per DESIGN.md MUST NOT 23, the client writes nothing to the
// filesystem, has no module-load side effects, and never touches
// stdout / stderr. All filesystem and logging concerns are the
// caller's responsibility.

import { build_query } from '../../dns_wire';
import {
    DoHAllProvidersFailedError,
    DoHError,
    DoHNoProvidersError,
    DoHTransportError,
    DoHUnexpectedContentTypeError,
    DoHUnexpectedStatusError,
} from './errors';

// Default DoH provider endpoints, used in the order shown when no
// `providers` option is supplied to [DoHClient].
export const DEFAULT_GOOGLE     = 'https://dns.google/dns-query';
export const DEFAULT_CLOUDFLARE = 'https://cloudflare-dns.com/dns-query';
export const DEFAULT_QUAD9      = 'https://dns.quad9.net/dns-query';

// MediaType is the MIME type defined by RFC 8484 §6 for DoH messages.
export const DOH_MEDIA_TYPE = 'application/dns-message';

// Default per-request timeout (10s) matches dnsdata-go's
// http.Client{Timeout: 10*time.Second}.
export const DOH_DEFAULT_TIMEOUT_MS = 10_000;

// RFC 8484 §4.2.1 caps DoH response sizes implicitly at the EDNS UDP
// payload size we request (4096). dnsdata-go caps at 64 KiB
// defensively; we match.
const DOH_MAX_RESPONSE_BYTES = 64 * 1024;

// DefaultProviders returns a fresh copy of the default provider list
// (Google → Cloudflare → Quad9). Each call yields an independent
// array so the caller may freely mutate the result, matching
// dnsdata-go's `DefaultProviders()` semantics.
export function default_providers(): string[] {
    return [DEFAULT_GOOGLE, DEFAULT_CLOUDFLARE, DEFAULT_QUAD9];
}

// fetch_fn is the minimum subset of the `fetch` API the DoH client
// uses. Tests inject a stub via [DoHClientOptions.fetch_fn]; production
// callers either let [DoHClient] use the global `fetch` (Node ≥ 18,
// browsers) or pass their own (e.g. an undici client with custom TLS).
export type FetchFn = (input: string, init?: RequestInit) => Promise<Response>;

export interface DoHClientOptions {
    // Provider URLs to try in registration order. An empty / omitted
    // list is normalised to the default set (Google → Cloudflare → Quad9).
    providers?: readonly string[];

    // Per-request timeout in milliseconds. Default 10000. Applied via
    // AbortController so it composes cleanly with caller-supplied
    // AbortSignal.
    timeout_ms?: number;

    // User-Agent header sent on every request. Default "dnsdata-js/doh".
    user_agent?: string;

    // Fetch implementation for tests / custom transports. Defaults to
    // the global `fetch` (Node ≥ 18, browsers). Throws at construction
    // time if no fetch is available and none is supplied.
    fetch_fn?: FetchFn;
}

export interface DoHQueryOptions {
    // Caller-supplied cancellation. Honoured for every provider
    // attempt and composed with the per-request timeout. When the
    // signal aborts before any provider succeeds, the resulting
    // DoHAllProvidersFailedError wraps a DoHTransportError whose
    // cause is the AbortError.
    signal?: AbortSignal;
}

// DoHClient is a DNS-over-HTTPS resolver with provider failover.
// Construct with options; all fields are immutable after construction
// so concurrent calls against a single client are safe.
//
// Ports the dnsdata-go `doh.Client` type.
export class DoHClient {
    private readonly _providers: readonly string[];
    private readonly _timeout_ms: number;
    private readonly _user_agent: string;
    private readonly _fetch: FetchFn;

    public constructor(opts: DoHClientOptions = {}) {
        const raw = opts.providers ?? [];
        this._providers = raw.length === 0
            ? default_providers()
            : [...raw];
        this._timeout_ms = opts.timeout_ms ?? DOH_DEFAULT_TIMEOUT_MS;
        this._user_agent = opts.user_agent ?? 'dnsdata-js/doh';

        const fetch_impl = opts.fetch_fn ?? get_global_fetch();
        if (!fetch_impl) {
            throw new DoHError(
                'doh: no fetch implementation available; pass fetch_fn explicitly or use Node ≥ 18',
            );
        }
        this._fetch = fetch_impl;
    }

    // Fresh copy of the configured provider list. Mutation of the
    // returned array does not affect the client.
    public providers(): string[] {
        return [...this._providers];
    }

    // Issue a DoH query for (qname, qtype) with class IN and the DO
    // bit set. Returns the raw DNS response message bytes from the
    // first provider that succeeds.
    //
    // Throws DoHNoProvidersError if no providers are configured, and
    // DoHAllProvidersFailedError if every provider failed.
    public async query(qname: string, qtype: number, opts: DoHQueryOptions = {}): Promise<Uint8Array> {
        const q = build_query(qname, qtype);
        return this.query_raw(q, opts);
    }

    // Send a prebuilt DNS query message via DoH and return the
    // response bytes from the first provider that succeeds.
    //
    // Failover policy: the providers are tried in registration order.
    // Network errors and non-2xx responses are treated as failover
    // triggers; a 2xx response with the right Content-Type is returned
    // immediately even when the embedded DNS RCODE is non-zero (that
    // is a DNS-level error, not a transport-level one).
    public async query_raw(query: Uint8Array, opts: DoHQueryOptions = {}): Promise<Uint8Array> {
        if (this._providers.length === 0) {
            throw new DoHNoProvidersError();
        }

        let first_err: unknown = null;
        for (const url of this._providers) {
            try {
                return await this._send_one(url, query, opts.signal);
            } catch (err) {
                if (first_err === null) first_err = err;
                // Try next provider.
            }
        }
        // Defensive: providers list was non-empty but every iteration
        // produced neither a response nor an error. Should be
        // unreachable; mirrors dnsdata-go's defensive check.
        throw new DoHAllProvidersFailedError(first_err);
    }

    // sendOne performs one HTTP POST against url. Throws a subclass
    // of DoHError on failure.
    private async _send_one(url: string, query: Uint8Array, signal?: AbortSignal): Promise<Uint8Array> {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this._timeout_ms);

        // Compose caller's signal with our timeout. The first one to
        // abort wins.
        const on_caller_abort = () => controller.abort();
        if (signal) {
            if (signal.aborted) {
                clearTimeout(timer);
                throw new DoHTransportError(url, new Error('aborted by caller'));
            }
            signal.addEventListener('abort', on_caller_abort, { once: true });
        }

        let resp: Response;
        try {
            // `fetch` accepts a Uint8Array body in both Node 18+ undici
            // and browsers. Copy into a fresh ArrayBuffer-backed view
            // to avoid any sharing surprises with the caller's buffer.
            const body = new Uint8Array(query.byteLength);
            body.set(query);

            resp = await this._fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': DOH_MEDIA_TYPE,
                    'Accept': DOH_MEDIA_TYPE,
                    'User-Agent': this._user_agent,
                },
                body,
                signal: controller.signal,
            });
        } catch (err) {
            throw new DoHTransportError(url, err);
        } finally {
            clearTimeout(timer);
            if (signal) signal.removeEventListener('abort', on_caller_abort);
        }

        if (resp.status < 200 || resp.status >= 300) {
            // Best-effort drain so the connection can be reused. We
            // intentionally ignore the body's contents — arbitrary
            // upstream error pages should not be loaded into memory.
            try { await resp.arrayBuffer(); } catch { /* ignore */ }
            throw new DoHUnexpectedStatusError(url, resp.status);
        }

        // RFC 8484 §6 — tolerate parameters such as
        // `application/dns-message; charset=utf-8` by matching only the
        // media-type prefix.
        const ct = resp.headers.get('content-type') ?? '';
        if (!ct.startsWith(DOH_MEDIA_TYPE)) {
            try { await resp.arrayBuffer(); } catch { /* ignore */ }
            throw new DoHUnexpectedContentTypeError(url, ct);
        }

        let buf: ArrayBuffer;
        try {
            buf = await resp.arrayBuffer();
        } catch (err) {
            throw new DoHTransportError(url, err);
        }
        if (buf.byteLength > DOH_MAX_RESPONSE_BYTES) {
            // Truncate defensively. dnsdata-go uses io.LimitReader for
            // the same effect; here we just slice.
            return new Uint8Array(buf, 0, DOH_MAX_RESPONSE_BYTES);
        }
        return new Uint8Array(buf);
    }
}

// get_global_fetch returns the runtime's global fetch when available
// (Node ≥ 18, browsers), or undefined otherwise. The [DoHClient]
// constructor turns undefined into a typed error so tests can run on
// any Node version with an injected stub.
function get_global_fetch(): FetchFn | undefined {
    const g = globalThis as { fetch?: FetchFn };
    return typeof g.fetch === 'function' ? g.fetch.bind(globalThis) : undefined;
}
