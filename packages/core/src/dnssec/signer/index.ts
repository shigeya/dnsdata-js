// Zone signer: key generation and loading, DS and trust-anchor
// derivation, NSEC chains, and whole-zone signing. Ports dnsdata-go
// `dnssec/signer` (UP-013). Exported from the package entry point as
// the `signer` namespace, e.g. `signer.sign_zone(...)`.

export { SignerError, SignerKeyFormatError, SignerUnsupportedAlgorithmError } from './errors';
export {
    FlagZone,
    FlagSEP,
    FlagsKSK,
    FlagsZSK,
    Key,
    generate_key,
    new_key,
    parse_pkcs8_pem,
} from './key';
export { parse_bind_private } from './bind';
export { DigestSHA256, DigestSHA384, root_anchors } from './ds';
export { build_nsec } from './nsec';
export { rrsig_labels } from './names';
export { sign_zone } from './sign';
export type { SignOptions } from './sign';
