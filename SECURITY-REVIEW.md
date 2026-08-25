# Keryx DTLS/SRTP internal security review

**Scope:** `src/Keryx.Dtls` (DTLS 1.2 handshake state machine + record layer + DTLS-SRTP key
export) and `src/Keryx.Srtp` (SRTP/SRTCP protect/unprotect), plus the `Keryx.PeerConnection` glue
that wires them into a WebRTC session.

**Date:** 2026-08. **Branch:** `feat/dtls-hardening`, cut from keryx `origin/main` and kept current
with it (merged through v0.1.2, which added RTP-perf and RFC 4588 RTX).

**Reviewer:** structured internal adversarial review, one engineer plus fan-out analysis subagents.
Cryptographic primitives (`AesGcm`, `AesCounterMode`/`Aes`, `HMACSHA1`/`HMACSHA256`,
`ECDiffieHellman`, `ECDsa`) come from `System.Security.Cryptography` and were treated as correct and
out of scope — the review targets the *protocol glue*: handshake verification, key derivation,
nonce/IV construction, replay handling, and validation completeness.

## What this review is, and is not

This is a **structured internal review with an adversarial test suite**, not a third-party audit. It
does not replace an external cryptographic audit, and it did not include fuzzing, formal
verification, side-channel measurement, or a review of the BCL primitives. Timing side channels
beyond the constant-time tag/secret comparisons noted below were not measured. The residual-risk
list at the end is written for whoever performs that external audit.

Every claim below is tagged **measured** (a test fails when the property is violated — I reverted the
fix and watched the test go red) or **reasoned** (I traced the code and the RFC but there is no
red-on-tamper test, usually because the property is not one a test can force, e.g. constant-timeness).
The bar for this review was: *a security claim without a failing-on-tamper test is worthless.* Where
a checklist item is **reasoned**, that is called out honestly rather than dressed up as proven.

## Method

1. Read every file in both projects and the `PeerConnection` DTLS/SRTP wiring against RFC 6347 /
   5246 / 7627 / 5705 / 5764 / 8422 (DTLS) and RFC 3711 / 7714 / 4585 / 4588 (SRTP).
2. For each checklist item, wrote an adversarial test that injects or rewrites the exact bytes a
   hostile peer or off-path injector would, and asserted Keryx fails **closed**.
3. Where the test passed against existing code, recorded it as PASS (already correct, now proven).
   Where it failed, fixed the code and recorded it as FIXED, keeping the test as a regression.
4. Re-ran the full keryx suite (`TreatWarningsAsErrors`, 0 warnings) green after every change.

## Findings summary

Six hardening commits on this branch, every one carrying an RFC-cited regression test that fails
against the previous code:

| Commit | Severity | What it closed |
| --- | --- | --- |
| `Reject DTLS 1.0 ClientHellos and duplicate handshake messages` | High | Version-downgrade acceptance; renegotiation/duplicate-message state rewrite (~10x reflected amplification via injected ClientHello) |
| `Refuse to connect when the remote SDP carries no a=fingerprint` | Critical | Unauthenticated session: a stripped `a=fingerprint` left the DTLS pin empty and a full session reached Connected with encryption but no authentication |
| `Stop unauthenticated DTLS records from ending a handshake` | High (DoS) x4 | Epoch-0 anti-replay wedge; fatal CCS retransmission; reassembler slot-exhaustion; fatal malformed-fragment. Plus a blank-fingerprint fail-open |
| `Maintain the SRTP sender's rollover counter by counting wraps` | Critical | SRTP packet-index reuse → AES-CM two-time pad / AES-GCM nonce reuse (GHASH-subkey recovery → forgery); SRTCP index wrap |
| `Validate peer ECDHE points on the curve, and stop allocating SRTP state pre-auth` | Medium / High (DoS) | Invalid-curve defence rested on an undocumented platform side effect; unauthenticated per-SSRC state allocation |
| `Bound the fragment-interval list and reject unimplementable SRTP profiles` | Medium (DoS) | Quadratic fragment-merge CPU burn inside the transport lock; late-throwing SRTP profile misconfiguration |

## Checklist ledger

### Handshake (DTLS 1.2, Keryx usually server, peer `active`)

**Certificate fingerprint validated against SDP `a=fingerprint`; mismatch aborts** — **FIXED + PASS.**
- Tampered fingerprint aborts: `DtlsFingerprintPinningTests.An_offer_pinning_the_wrong_sha256_fingerprint_is_refused` and the transport-level `DtlsHandshakeLoopbackTests.A_wrong_expected_fingerprint_aborts_the_handshake_on_the_{client,server}`. **Measured.**
- Missing fingerprint fails closed (was fail-open, reached Connected unauthenticated — measured against old code): `DtlsFingerprintPinningTests.An_offer_with_no_fingerprint_is_refused`. **Measured, FIXED.**
- Non-sha-256 fingerprint refused: `An_offer_pinning_a_non_sha256_fingerprint_is_refused`. **Measured** (diagnostic — the old code already failed closed here by digest mismatch).
- Blank pin no longer silently means "no pinning": `AdversarialHandshakeTests.A_blank_expected_fingerprint_is_refused_rather_than_treated_as_no_pinning`. **Measured, FIXED.**

**CertificateVerify signature actually checked** — **PASS.** `DtlsHandshakeLoopbackTests.A_tampered_client_CertificateVerify_aborts_the_server` (aborts with `decrypt_error`). **Measured.** The signature is verified over the raw handshake transcript captured *before* the CertificateVerify message is appended (`HandleCertificateVerifyLocked`), which is the correct transcript per RFC 5246 §7.4.8.

**Finished MAC verified over the correct transcript hash** — **PASS.** `A_tampered_client_Finished_aborts_the_server` (aborts with `decrypt_error`); verify_data compared with `CryptographicOperations.FixedTimeEquals`. **Measured.** verify_data length (12) and labels (`client finished`/`server finished`) pinned by `TlsPrfTests.Verify_data_is_twelve_bytes_under_the_rfc5246_finished_labels`. **Measured** (structural — a Keryx-to-Keryx handshake could not catch a label swap).

**No version downgrade below 1.2** — **FIXED.** A ClientHello whose `client_version` is DTLS 1.0 was answered with a 1.2 ServerHello; it is now refused with `protocol_version`: `AdversarialHandshakeTests.A_ClientHello_offering_DTLS_1_0_is_refused_with_protocol_version`. **Measured** (old code aborted later with `decrypt_error`, not at all as a version check). The record-layer 1.0 version on the initial ClientHello is still accepted, per RFC 6347 §4.1.

**Unexpected / renegotiation ClientHellos rejected** — **FIXED.** Every handshake message that mutates negotiated state now rejects a second occurrence with `unexpected_message`. `AdversarialHandshakeTests.An_injected_second_ClientHello_does_not_restart_the_server_handshake` (established server, no new flight — the ~10x amplification vector) and `An_injected_ClientHello_mid_handshake_is_rejected_as_unexpected`. **Measured.**

**Cookie / HelloVerifyRequest anti-DoS** — **ACCEPTED-RISK (documented).** Keryx does not send HelloVerifyRequest as a server. This is deliberate: ICE validates the peer address before DTLS starts, which is why WebRTC stacks (BoringSSL peers included) skip the cookie exchange. Documented in `docs/layers/dtls.md` ("Decisions and simplifications") and in the `DtlsTransport` class remarks. **Reasoned.** The client side does handle a received HelloVerifyRequest, and rejects a second one (`HandleHelloVerifyRequestLocked`).

**Fragment reassembly can't be driven to OOM / overlapping-fragment attacks; retransmit timers bounded** — **FIXED + PASS.**
- Per-message length capped at 128 KiB before allocation, transcript capped at 512 KiB: `HandshakeReassemblyTests.An_absurdly_large_message_length_is_rejected`. **Measured.**
- Overlapping fragments merged by interval, not counted: `Overlapping_fragments_reassemble_correctly`. **Measured** (a naive received-bytes counter would mark a message complete with holes — this proves the interval bitmap).
- Slot-exhaustion no longer fatal (was `internal_error` from one 301-byte datagram): `AdversarialHandshakeTests.Filling_the_reassembly_slots_cannot_abort_the_handshake`; the limit now evicts the partial furthest ahead of the next expected message_seq rather than the arrival. **Measured, FIXED.**
- Quadratic interval-merge CPU burn (one-byte fragments at alternating offsets, ~1s/832 KiB inside the transport lock) capped at 64 intervals: `Pathological_fragmentation_is_abandoned_rather_than_tracked_quadratically`, with `Contiguous_fragments_delivered_out_of_order_still_reassemble` proving the legitimate path is untouched. **Measured, FIXED.**
- Malformed fragment header at epoch 0 no longer fatal: `A_malformed_epoch_zero_handshake_fragment_is_discarded`. **Measured, FIXED.**
- Retransmit timer: exponential backoff capped at `MaxRetransmitTimeout` (60s default), overall handshake bounded by `HandshakeTimeout`. `Handshake_times_out_when_the_peer_never_answers`. The backoff *cap* itself is **reasoned** (read code); the overall timeout is **measured**.

**Master-secret / key-block derivation matches RFC 5246 §6.3 / RFC 5705 exporter for `EXTRACTOR-dtls_srtp`; SRTP key/salt lengths correct** — **PASS.**
- TLS 1.2 PRF against a published vector: `TlsPrfTests.Prf_matches_the_published_tls12_sha256_vector`. **Measured (RFC/published vector).**
- Master-secret seed order client-then-server (RFC 5246 §8.1): `Master_secret_seed_order_is_client_random_then_server_random`; key-block seed order server-then-client (the reversed one, §6.3): `Key_block_seed_order_is_server_random_then_client_random`; exporter order client-then-server (RFC 5705 §4): `Exporter_seed_order_is_client_random_then_server_random`; the three are proven distinct: `The_three_derivations_do_not_share_a_seed_order`. Extended master secret over session_hash (RFC 7627 §4): `Extended_master_secret_uses_the_session_hash_and_no_randoms`. All **measured (structural)** — these are exactly the bugs a Keryx-to-Keryx interop test cannot see.
- Exported material identical on both peers: `DtlsHandshakeLoopbackTests.Exported_keying_material_matches_on_both_sides`. **Measured.**
- RFC 5764 §4.2 key/salt split ordering (keys first, then salts) and 60-byte length for `SRTP_AES128_CM_HMAC_SHA1_80`: `DtlsSrtpKeyMaterialTests.Split_UsesTheRfc5764Ordering`, `RequiredLength_MatchesTheProfile`. **Measured.**

### SRTP / SRTCP

**Replay protection: sliding window present and correct (RFC 3711 §3.3.2); replayed/old packet rejected** — **PASS.**
- `SrtpRoundTripTests.ReplayedPacket_IsRejected` / `SrtcpRoundTripTests.ReplayedPacket_IsRejected`; window edges in `SrtpPacketIndexTests.PacketsOlderThanTheWindowAreRejected`, `PacketsInsideTheWindowAreAcceptedOnceEach`, `SlidingForwardForgetsIndicesThatFallOutOfTheWindow`. **Measured.**
- Window updated only *after* authentication (a forged far-future sequence number must not slide the window and starve the real sender): `SrtpSenderIndexTests.A_forged_packet_with_a_far_future_sequence_number_does_not_slide_the_window`. **Measured** (behaviour was already correct; it was previously unproven).

**Auth-tag verification is constant-time and checked BEFORE decrypt; truncated/forged tags rejected** — **PASS.**
- AES-CM-HMAC: tag compared with `CryptographicOperations.FixedTimeEquals` and the function returns `false` before `_rtpCipher.Transform` is ever called (`SrtpAesCmHmacSha1Transform` lines ~115/172). Auth-before-decrypt and constant-time are **reasoned** (traced); forged-tag rejection is **measured** (`SrtpRoundTripTests.TamperedPacket_IsRejected`, `SrtcpRoundTripTests.TamperedPacket_IsRejected`).
- GCM: `AesGcm.Decrypt` verifies the tag internally and yields no plaintext on mismatch. Tamper rejection **measured** against the RFC 7714 vector: `Rfc7714VectorTests.Section16_1_2_UnprotectRtp_RejectsATamperedVector`, `Section17_1_UnprotectRtcp_RejectsATamperedVector`.
- Truncated / malformed packets rejected without OOB: `SrtpRobustnessTests.TruncatedAndMalformedPackets_ReturnFalseWithoutThrowing`, `RtpPacketWithAnOversizedHeaderExtension_IsRejected`. **Measured.**

**IV/counter construction per §4.1.1 (SSRC‖index); no nonce reuse across ROC rollover; ROC handling correct** — **FIXED + PASS.**
- AES-CM IV offset against the published RFC 3711 Appendix B.2 vector: `Rfc3711VectorTests.B2_PacketIv_MatchesPublishedOffset`, keystream `B2_KeystreamSegment_MatchesPublishedBlocks`. **Measured (RFC vector).**
- **Sender index reuse (FIXED, Critical):** the send path used the receiver-side Appendix A estimator, which could reuse an index two ways — protecting the same SSRC+seq twice, and a forward jump after a wrap rewinding the index by 2^16. The sender now counts wraps and refuses any index at or below the highest emitted: `SrtpSenderIndexTests.Protecting_the_same_sequence_number_twice_is_refused` and `A_forward_jump_after_a_wrap_cannot_rewind_the_packet_index` (asserts identical plaintext at the reused index yields *different* ciphertext), with `A_normal_sequence_number_wrap_still_protects` guarding the legitimate path. **Measured, FIXED.** Reverting the guard turns two of these red — re-confirmed post-merge.
- Receiver ROC estimation (Appendix A): `SrtpPacketIndexTests.EstimateRolloverCounter_FollowsAppendixA`, `Commit_AppliesTheSection331UpdateRules`, out-of-order-across-wrap delivery `SrtpRoundTripTests.SequenceNumberWrap_HandlesOutOfOrderDelivery`. **Measured.**
- **RTX interaction (checked post-merge):** v0.1.2 added RFC 4588 retransmission. RTX resends flow through `SendProtectedRtp` → `ProtectRtp` under the **repair SSRC** with its own monotonic sequence space; the SSRC is part of the AES-CM IV, so a media packet and its RTX copy never share a (key, IV). The 27 integration tests (incl. `RtxSoakTests`, `RtxLossSweepTests`) run through the hardened `SrtpEncryptContext` without tripping the reuse guard. **Measured** (integration).

**SRTCP E-flag + index handling; RFC 7714 AEAD nonce unique per packet** — **PASS + FIXED.**
- E-flag set/clear and 31-bit index: `SrtcpRoundTripTests.ProtectedPacket_CarriesTheEncryptFlagAndAnIncrementingIndex`, `PacketWithTheEFlagClear_IsAuthenticatedAndPassedThroughInTheClear`; index masking and AAD coverage via `Rfc7714VectorTests.Section17_1_UnprotectRtcp_RejectsAnAlteredIndex`. **Measured (RFC vector).**
- AEAD nonce matches the published RFC 7714 §16/§17 IV: `Section16_RtpNonce_MatchesPublishedIv`, `Section17_RtcpNonce_MatchesPublishedIv`. **Measured (RFC vector).**
- SRTCP index wrap (FIXED): the index incremented mod 2^31 and silently wrapped, repeating nonces; it now stops at the RFC 3711 §9.2 limit: `SrtpSenderIndexTests.The_srtcp_index_stops_at_the_rfc3711_limit_rather_than_wrapping`. **Measured, FIXED.**
- SRTP/SRTCP separate per-SSRC replay windows: `SrtcpRoundTripTests.DistinctSsrcs_KeepIndependentSrtcpIndices`, `SrtpRoundTripTests.DistinctSsrcs_KeepIndependentState`. **Measured.**

**Key lifetime / packet-count limits noted** — **PASS (partial) + noted.**
- SRTCP: hard stop at 2^31 packets/master key (RFC 3711 §9.2), measured above.
- SRTP: the 48-bit packet index cannot be reused within a master key — the sender refuses a repeat and would throw at exhaustion rather than wrap. There is **no** proactive rekey/count-limit enforcement below 2^48; a WebRTC session is rekeyed by a new DTLS handshake long before then. **Reasoned**; listed as residual risk.

### DTLS-SRTP key export and ECDHE (supporting)

**RFC 5705 exporter, no context, label `EXTRACTOR-dtls_srtp`** — **PASS**, see key-block ledger above.

**ECDHE peer-point validation (RFC 8422 §5.4.1)** — **FIXED (defence-in-depth).** The on-curve check previously relied on `ECParameters.Validate()`, which does no curve arithmetic, so the real rejection came from the platform's key import (verified on macOS: removing the explicit check leaves the tests green because the Apple provider rejects the import). An explicit `y² = x³ − 3x + b (mod p)` check, coordinate-range check, and point-at-infinity rejection were added: `EcdheTests.A_point_off_the_curve_is_rejected`, `The_point_at_infinity_is_rejected`, `A_coordinate_not_reduced_modulo_the_field_prime_is_rejected`, `A_point_that_is_not_uncompressed_is_rejected`, `A_point_of_the_wrong_length_is_rejected`. **Measured** (though the platform also catches it today — this removes the dependence on that and is portable). Pre-master secret is the raw X coordinate, not a KDF'd value (RFC 8422 §5.10): `The_pre_master_secret_is_the_raw_x_coordinate_and_not_a_kdf_of_it`. **Measured.** Keryx uses an ephemeral key per handshake, so there is no static scalar for an invalid-curve attack to accumulate against today; the value of the fix is that a future change caching the key cannot silently become key recovery.

## Threat model

**Defends against:**
- A signalling-channel attacker who tampers with, strips, or downgrades the SDP `a=fingerprint` — the session fails closed rather than completing unauthenticated (RFC 8827 §6.5 trust anchor enforced).
- A man-in-the-middle on the media path presenting a different certificate — fingerprint pinning aborts the handshake.
- Tampering with any authenticated handshake message (Certificate, CertificateVerify, Finished) — fails closed.
- Forged, tampered, truncated, or replayed SRTP/SRTCP packets — rejected before the payload is trusted, with no state mutation on failure.
- Off-path / on-path injectors sending forged unauthenticated DTLS records to the port: cannot wedge the anti-replay window, cannot end a handshake with a malformed fragment, cannot force unbounded memory or quadratic CPU, cannot make the server reflect a certificate flight, cannot allocate per-SSRC SRTP state.
- Version downgrade to DTLS 1.0 and renegotiation attempts.

**Explicitly does NOT defend against (by design or scope):**
- A signalling channel with no integrity of its own: fingerprint pinning is only as trustworthy as the SDP delivery. Keryx assumes the application authenticates its signalling.
- Server-side connection-flood DoS *before* ICE validation: no HelloVerifyRequest cookie (accepted risk — ICE address validation precedes DTLS).
- Timing side channels beyond the constant-time tag/secret comparisons: parsing, state dispatch, and error paths are not constant-time and their timing may reveal message structure.
- Anything the BCL primitives get wrong: their correctness and side-channel resistance are assumed.
- Compromise of the local private key or the peer's, session resumption/renegotiation attacks (neither is implemented), and DTLS 1.0/1.3.

## Shared-key encrypt-once public-broadcast mode (`broadcast-scale.md` §5)

This mode (`Keryx.Broadcast.SharedKeyBroadcastTier`, `PublicBroadcastKey`) deliberately **replaces the
per-viewer pairwise SRTP guarantee with a group guarantee** so a public broadcast can be encrypted once
and fanned out to N viewers as byte-identical ciphertext. It is opt-in, off by default everywhere, and
gated on owner sign-off of this section. It is **for public content only** and is not interoperable with
stock browsers (it requires a client whose SRTP layer accepts an injected key — a Keryx client or relay).

**What changes.** Every enrolled viewer receives the *same* SRTP master key. Because SRTP AEAD is
symmetric, a keyholder can both decrypt and **forge** valid broadcast packets. Confidentiality within the
viewer set is therefore nil by design (any viewer may read the stream — the product, not a leak; the
trust model of a public HLS/DASH CDN), and per-viewer media *authentication* degrades from "from the SFU"
to "from someone holding the broadcast key".

**Defends against / preserves:**
- The **ingest leg** (broadcaster→SFU) keeps its own DTLS-SRTP keys; the SFU decrypt/re-encrypt boundary
  is intact. A viewer's key gives nothing upstream.
- **Isolation from private media.** The key is minted from a CSPRNG (`CreateForPublicContent`), never from
  any DTLS exporter, and never mixed with one. On the client the shared key is applied **only** to the
  enumerated broadcast SSRC(s) (`InstallPublicBroadcastReceiveKey` is SSRC-scoped); every other m-line,
  including any private one on the same transport, keeps its DTLS-derived keys. A broadcast SSRC that
  fails to authenticate is dropped, never retried against the private keys.
- **No enrollment of a media-sending viewer.** `SharedKeyBroadcastTier.Enroll` throws for any session
  with a receiving media m-line (recvonly/sendrecv from the SFU's view, checked on both the desired and
  the negotiated direction) — such a viewer could send media under the shared key and forge toward others.
- **No path from a private/1:1/mixed room.** The mode exists only inside the broadcast fan-out component,
  behind the public-named key type; there is no per-`PeerConnection` "use shared key" switch, and a
  session may be enrolled in exactly one broadcast's key.
- **Key transport** rides each viewer's already-DTLS-authenticated data channel (a Keryx-defined
  `PublicBroadcastKeyMessage`), so it is confidential and authenticated per viewer even though the media
  key is shared. Epoch rotation mints a fresh key and bounds exposure; viewers hold two epochs across the
  switch.

**Explicitly does NOT defend against (accepted, by design):**
- **Keyholder forgery.** Any enrolled viewer (or anyone who obtains the broadcast key) who *also* has the
  network position to spoof the SFU's 5-tuple to another viewer, within that viewer's replay/ROC window,
  can inject cryptographically-valid forged media into that viewer's player. This is the stated trade:
  per-viewer media authentication for scale. Mitigations retained — receivers accept only the established
  5-tuple, replay windows hold, epoch rotation bounds exposure — but a keyholder forgery is valid and the
  design does not claim otherwise.
- **Confidentiality against enrolled viewers.** Non-existent by construction; enrollment is open for
  public content.

## Residual risk (for a future external auditor)

1. **No fuzzing.** The parsers (`HandshakeCodec`, `DtlsRecordReader`, `RtpHeaderView`) were reviewed and exercised by targeted adversarial tests, but not fuzzed. A structured fuzzer over the record/handshake/SRTP-packet parsers is the highest-value next step.
2. **Timing side channels.** Only tag and secret comparisons are constant-time. Parse/dispatch/error timing is not analysed or measured. An auditor should assess whether error-path timing leaks message structure or padding.
3. **No proactive SRTP rekey below 2^48 packets.** Index reuse is impossible (the sender refuses it), but there is no automatic rekey/renegotiation at a packet-count threshold; the design relies on a session being shorter than that. Worth confirming against the intended deployment's session lifetimes.
4. **Server-side pre-ICE DoS.** The no-cookie decision is sound for the WebRTC model but should be re-examined for any deployment where DTLS could be reached before ICE validation.
5. **BCL primitive trust.** The review assumes `System.Security.Cryptography` is correct and side-channel-resistant on every target platform/runtime; the ECDHE on-curve finding showed one place where relying on platform behaviour was implicit — an auditor should look for others.
6. **Not an external audit.** This document records an internal review only. It has not been independently verified.
