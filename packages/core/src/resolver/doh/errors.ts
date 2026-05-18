// Error hierarchy for the DoH client.
//
// Ports the dnsdata-go `resolver/doh/errors.go` module
// (originated in dnsdata-go v0.1.0; tracked here as UP-007).
//
// Go uses sentinel errors and `errors.Is` for classification. The TS
// port mirrors the same taxonomy with subclasses so callers can
// discriminate via `instanceof`:
//
//   - DoHError              — umbrella for every transport-level failure
//   - DoHNoProvidersError   — empty provider list
//   - DoHAllProvidersFailedError — every provider errored (first cause kept)
//   - DoHUnexpectedStatusError   — non-2xx HTTP status
//   - DoHUnexpectedContentTypeError — wrong Content-Type
//   - DoHResponseError      — RCODE != 0 or malformed DNS message
//
// All classes inherit from DoHError, matching the dnsdata-js
// AuthResolverError pattern (see resolver_auth.ts).

export class DoHError extends Error {
    public constructor(message: string) {
        super(message);
        this.name = 'DoHError';
    }
}

// Returned when the configured provider list is empty.
export class DoHNoProvidersError extends DoHError {
    public constructor() {
        super('doh: no providers configured');
        this.name = 'DoHNoProvidersError';
    }
}

// Returned when every configured provider errored or returned a non-2xx
// response. `cause` carries the first provider's underlying error so
// callers can still discriminate via the underlying type, mirroring
// Go's `errors.Join(ErrAllProvidersFailed, firstErr)` shape.
export class DoHAllProvidersFailedError extends DoHError {
    public readonly cause: unknown;
    public constructor(cause: unknown) {
        super(`doh: all providers failed: ${error_message(cause)}`);
        this.name = 'DoHAllProvidersFailedError';
        this.cause = cause;
    }
}

// Returned when a provider answered with a non-2xx HTTP status code.
export class DoHUnexpectedStatusError extends DoHError {
    public readonly url: string;
    public readonly status: number;
    public constructor(url: string, status: number) {
        super(`doh: ${url} returned HTTP ${status}`);
        this.name = 'DoHUnexpectedStatusError';
        this.url = url;
        this.status = status;
    }
}

// Returned when a provider answered with a Content-Type other than
// `application/dns-message`.
export class DoHUnexpectedContentTypeError extends DoHError {
    public readonly url: string;
    public readonly content_type: string;
    public constructor(url: string, content_type: string) {
        super(`doh: ${url} returned content-type "${content_type}"`);
        this.name = 'DoHUnexpectedContentTypeError';
        this.url = url;
        this.content_type = content_type;
    }
}

// Returned when a transport attempt (fetch) failed before any response
// could be classified. `cause` carries the underlying error.
export class DoHTransportError extends DoHError {
    public readonly url: string;
    public readonly cause: unknown;
    public constructor(url: string, cause: unknown) {
        super(`doh: post ${url}: ${error_message(cause)}`);
        this.name = 'DoHTransportError';
        this.url = url;
        this.cause = cause;
    }
}

// Returned by [DoHClient.resolve] when the DNS response itself is
// malformed or carries a non-zero RCODE. Distinguishes "DNS-level
// failure" from "transport-level failure" — Go's ErrResolverResponse.
export class DoHResponseError extends DoHError {
    public constructor(message: string) {
        super(`doh: bad response: ${message}`);
        this.name = 'DoHResponseError';
    }
}

function error_message(err: unknown): string {
    if (err instanceof Error) return err.message;
    return String(err);
}
