// build_answer: the validated RRset carried on Result.answer.
//
// Ports dnsdata-go `verifier/answer.go`. Result stays plain JSON
// (DESIGN.md §4 MUST 10), so the RDATA octets are held as base64 and
// the validity window as RFC 3339 UTC strings — the same text Go's
// encoding/json produces for []byte and time.Time.

import { DNSSecZone, KeyVerifyMode } from '../dnssec/dnssec_zone';
import { SigStatus } from '../dnssec/sigcheck';
import { WireBuilder } from '../wire/dns_wire_util';
import { Answer, AnswerRecord, AnswerSignature } from './result';
import { VerifierError } from './errors';
import { error_message } from './verifier';

// Octets of RDLENGTH in front of the RDATA written by get_wire_body.
const RDLENGTH_OCTETS = 2;
const MILLISECONDS_PER_SECOND = 1000;

// build_answer describes the (qname, qtype) RRset of z, which has just
// verified, with every RRSIG over it that verifies on its own.
export function build_answer(z: DNSSecZone, qname: string, qtype: number): Answer {
    const records: AnswerRecord[] = z.find_rrset(qname, qtype).map((rr) => {
        const b = new WireBuilder();
        try {
            rr.get_wire_body(b, z.get_registry());
        } catch (err: unknown) {
            throw new VerifierError(`verifier: answer ${rr.label}: ${error_message(err)}`);
        }
        return {
            name: rr.label,
            ttl: rr.ttl,
            class: rr.rrclass,
            type: rr.type,
            value: rr.value,
            rdata: Buffer.from(b.build().subarray(RDLENGTH_OCTETS)).toString('base64'),
        };
    });
    const signatures: AnswerSignature[] = z.find_rrsigs(qname, qtype)
        .filter((sig) => z.check_rrsig(qname, qtype, sig, KeyVerifyMode.None).status === SigStatus.Verified)
        .map((sig) => ({
            keyTag: sig.key_tag,
            algorithm: sig.algorithm,
            signer: sig.signer,
            labels: sig.labels,
            inception: rfc3339(sig.inception),
            expiration: rfc3339(sig.expire),
        }));
    return { name: qname, type: qtype, records, signatures };
}

// rfc3339 formats Unix seconds as Go's time.Time JSON does for a UTC
// time with no fractional second: "2026-01-01T00:00:00Z".
function rfc3339(unixSeconds: number): string {
    return new Date(unixSeconds * MILLISECONDS_PER_SECOND).toISOString().replace('.000Z', 'Z');
}
