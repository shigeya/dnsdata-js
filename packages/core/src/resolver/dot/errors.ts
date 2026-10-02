// Error hierarchy of the DNS-over-TLS client. Ports dnsdata-go
// `resolver/dot/errors.go`; callers discriminate with `instanceof`.

// DoTResolverError is the umbrella class of every DoTClient failure.
export class DoTResolverError extends Error {
    public constructor(message: string) {
        super(message);
        this.name = 'DoTResolverError';
    }
}

// Thrown when no server is configured.
export class DoTNoServersError extends DoTResolverError {
    public constructor() {
        super('dot: no servers configured');
        this.name = 'DoTNoServersError';
    }
}

// Thrown when every server failed; the first failure is `.cause`.
export class DoTAllServersFailedError extends DoTResolverError {
    public readonly cause: unknown;
    public constructor(cause: unknown) {
        super(`dot: all servers failed: ${error_message(cause)}`);
        this.name = 'DoTAllServersFailedError';
        this.cause = cause;
    }
}

// Thrown for a reply shorter than a DNS header.
export class DoTResponseTooShortError extends DoTResolverError {
    public constructor(length: number) {
        super(`dot: response too short: ${length} bytes`);
        this.name = 'DoTResponseTooShortError';
    }
}

// Thrown for a reply whose transaction ID is not the query's.
export class DoTIDMismatchError extends DoTResolverError {
    public constructor(response_id: number, query_id: number) {
        super(`dot: response transaction ID mismatch: response 0x${hex16(response_id)}, query 0x${hex16(query_id)}`);
        this.name = 'DoTIDMismatchError';
    }
}

// Thrown when resolve() cannot parse the response. A non-zero RCODE is
// not an error.
export class DoTResponseError extends DoTResolverError {
    public constructor(message: string) {
        super(`dot: bad response: ${message}`);
        this.name = 'DoTResponseError';
    }
}

// Thrown on a connection failure: dial, TLS handshake or server
// authentication, write, read.
export class DoTTransportError extends DoTResolverError {
    public readonly cause: unknown;
    public constructor(message: string, cause: unknown) {
        super(`dot: ${message}: ${error_message(cause)}`);
        this.name = 'DoTTransportError';
        this.cause = cause;
    }
}

// Thrown when a server attempt did not finish within the timeout.
export class DoTTimeoutError extends DoTResolverError {
    public constructor(operation: string, addr: string, timeout_ms: number) {
        super(`dot: ${operation} ${addr} timed out after ${timeout_ms}ms`);
        this.name = 'DoTTimeoutError';
    }
}

// Thrown when the caller's AbortSignal fired first.
export class DoTAbortedError extends DoTResolverError {
    public constructor() {
        super('dot: aborted by caller');
        this.name = 'DoTAbortedError';
    }
}

function hex16(n: number): string {
    return n.toString(16).padStart(4, '0');
}

function error_message(err: unknown): string {
    return err instanceof Error ? err.message : String(err);
}
