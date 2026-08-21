# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub Security Advisories
("Report a vulnerability" on the repository's Security tab). Do not open public issues for
security reports. You should receive an acknowledgement within a few days.

## Status: read this before deploying

Keryx implements its own DTLS 1.2 handshake and record layer and its own SRTP/SRTCP transforms
(protocol logic only — all cryptographic primitives are the platform's
`System.Security.Cryptography`).

**The DTLS and SRTP implementations have NOT received an independent security review.**
They are correctness-focused and verify everything the RFCs require — peer CertificateVerify over
the handshake transcript, Finished verify_data, certificate fingerprint pinning against the SDP
`a=fingerprint`, AEAD auth tags, anti-replay windows, constant-time tag comparisons — and these
behaviors are covered by tests, including tamper and replay cases. That is a necessary bar, not a
sufficient one. Until an independent review has been completed and noted here, do not use Keryx
to protect sensitive traffic in production.

Known, deliberate limitations of the current implementation are documented in
`docs/layers/dtls.md` and `docs/layers/srtp.md` (e.g. no DTLS session resumption or
renegotiation, no constant-time guarantees beyond the BCL primitives', no HelloVerifyRequest).

## Supported versions

Pre-1.0: only the latest 0.x release receives fixes.
