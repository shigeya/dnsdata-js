// Error hierarchy for the authoritative-DNS client. Ports dnsdata-go
// `resolver/auth/errors.go` and mirrors the sentinel-error taxonomy
// with subclasses so callers can discriminate via `instanceof`.

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

export function error_message(err: unknown): string {
    if (err instanceof Error) return err.message;
    return String(err);
}
