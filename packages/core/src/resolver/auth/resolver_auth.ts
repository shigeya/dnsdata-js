// Back-compat re-export shim. The auth resolver is now organised
// per dnsdata-go's split:
//
//   - errors.ts ← Auth*Error hierarchy + error_message helper
//   - client.ts ← Dialer interfaces, NodeDialer + connection wrappers,
//                 AuthClient (query / query_raw + UDP/TCP transports),
//                 normalize_addr / parse_addr helpers
//   - resolve.ts ← AuthClient.resolve via declaration merging
//
// External callers can keep importing
// '@dnsdata/core' or '.../resolver/auth/resolver_auth' — both
// surfaces continue to expose the same symbols. The side-effect
// import below guarantees the resolve() method is installed
// regardless of which entry point loads first.

export * from './index';
