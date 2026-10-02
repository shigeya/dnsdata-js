// `host:port` server addresses, shared by the auth and DoT clients.
// Mirrors Go's net.SplitHostPort / net.JoinHostPort for the shapes the
// clients accept: "host:port", "ipv4:port", "[ipv6]:port", and a bare
// host or IPv6 address that gets the default port.

const MAX_PORT = 65535;

// normalize_host_port returns addr with default_port when it has none.
// A bare IPv6 address is bracketed: `::1` → `[::1]:<port>`.
export function normalize_host_port(addr: string, default_port: number): string {
    if (has_port(addr)) return addr;
    return addr.includes(':') && !addr.startsWith('[') ? `[${addr}]:${default_port}` : `${addr}:${default_port}`;
}

// parse_host_port splits a normalized address into the bare host (no
// IPv6 brackets, as Node's net / tls / dgram expect) and the port.
// Throws Error for a malformed address.
export function parse_host_port(addr: string): { host: string; port: number } {
    if (addr.startsWith('[')) {
        const close = addr.indexOf(']');
        if (close < 0 || close + 1 >= addr.length || addr[close + 1] !== ':') {
            throw new Error(`invalid bracketed address: ${addr}`);
        }
        return { host: addr.slice(1, close), port: parse_port(addr, addr.slice(close + 2)) };
    }
    const last = addr.lastIndexOf(':');
    if (last < 0) {
        throw new Error(`missing port in address: ${addr}`);
    }
    return { host: addr.slice(0, last), port: parse_port(addr, addr.slice(last + 1)) };
}

function parse_port(addr: string, text: string): number {
    const port = Number(text);
    if (!Number.isInteger(port) || port < 0 || port > MAX_PORT) {
        throw new Error(`invalid port in address: ${addr}`);
    }
    return port;
}

// has_port reports whether addr already carries a port. A host with
// more than one ':' outside brackets is a bare IPv6 address.
function has_port(addr: string): boolean {
    if (addr.startsWith('[')) {
        const close = addr.indexOf(']');
        return close >= 0 && close + 1 < addr.length && addr[close + 1] === ':';
    }
    const colon = addr.indexOf(':');
    return colon >= 0 && colon === addr.lastIndexOf(':');
}
