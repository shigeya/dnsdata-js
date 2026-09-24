// In-memory authority for signed zones, usable as the verifier's
// Resolver. Ports dnsdata-go `resolver/memory` (UP-014). Exported from
// the package entry point as the `memory` namespace, e.g.
// `memory.new_authority(memory.with_zone('.', root), ...)`.

export { MemoryConfigError } from './errors';
export { Authority, new_authority, with_zone, with_fault } from './memory';
export type { Option } from './memory';
