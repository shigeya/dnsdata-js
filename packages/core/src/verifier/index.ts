// Barrel for the verifier package. External callers should import
// from here; internal cross-file imports use the per-file modules
// directly to keep the dependency graph explicit.

export * from './verdict';
export * from './result';
export * from './resolver';
export * from './cache';
export * from './errors';
export {
    Verifier,
    VerifierOptions,
    normalize_qname,
    qtype_mnemonic,
    check_aborted,
    is_abort_error,
    error_message,
} from './verifier';
export {
    validate,
    descendant_zones,
} from './chain';
export {
    try_cname,
    try_dname,
    synthesise_dname_target,
} from './alias';
export {
    prove_no_ds,
    prove_no_ds_with_nsec,
    prove_no_ds_with_nsec3,
    nsec_candidates,
    nsec3_candidates,
    bytes_equal,
    type NsecCandidate,
    type Nsec3Candidate,
} from './negative';
export {
    prove_no_data,
    prove_no_data_with_nsec,
    prove_no_data_with_nsec3,
    prove_nx_domain,
    prove_nx_domain_with_nsec,
    prove_nx_domain_with_nsec3,
    find_covering_nsec3,
    closest_encloser_nsec,
    ancestors_of,
    next_closer_name,
    longest_common_ancestor,
    canon_labels_trim,
} from './leaf_negative';
export {
    detect_wildcard,
    prove_qname_non_existence,
} from './wildcard';
