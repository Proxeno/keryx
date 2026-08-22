# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub Security Advisories
("Report a vulnerability" on the repository's Security tab). Do not open public issues for
security reports. You should receive an acknowledgement within a few days.

## Status: read this before deploying

Keryx implements its own DTLS 1.2 handshake and record layer and its own SRTP/SRTCP transforms
(protocol logic only — all cryptographic primitives are the platform's
`System.Security.Cryptography`).

**The DTLS and SRTP implementations have had a structured internal security review
(`SECURITY-REVIEW.md`) but NOT an independent external audit.** The internal review was adversarial:
it verifies everything the RFCs require — peer CertificateVerify over the handshake transcript,
Finished verify_data, certificate fingerprint pinning against the SDP `a=fingerprint`, AEAD auth
tags, anti-replay windows, constant-time tag comparisons — and each of those behaviors is backed by
a test that fails closed on tamper, replay, forgery, or downgrade. It also found and fixed real gaps
(a fail-open when the SDP carried no fingerprint, SRTP packet-index reuse, a version-downgrade
acceptance, and several unauthenticated-input DoS vectors); see `SECURITY-REVIEW.md` for the full
ledger, threat model, and residual-risk list. That is a meaningful bar, but it remains an internal
review, not a third-party audit, and it did not include fuzzing or side-channel measurement. Until
an independent external audit has been completed and noted here, do not use Keryx to protect
sensitive traffic in production.

Known, deliberate limitations of the current implementation are documented in
`docs/layers/dtls.md` and `docs/layers/srtp.md` (e.g. no DTLS session resumption or
renegotiation, no constant-time guarantees beyond the BCL primitives', no HelloVerifyRequest).

## Supported versions

Pre-1.0: only the latest 0.x release receives fixes.
