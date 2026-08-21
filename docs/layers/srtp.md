# Keryx.Srtp — design notes

RFC 3711 SRTP/SRTCP as a pure transform over wire bytes, keyed by raw material from DTLS-SRTP.

## Decisions

- **Depends only on `Keryx.Core`.** Keys arrive as bytes (`DtlsSrtpKeyMaterial.Split` performs the
  RFC 5764 §4.2 client/server split of the 60-byte exporter block); the 12-byte RTP fixed header
  is parsed locally. SRTP is a transform, not a media layer.
- **Profiles:** `SRTP_AES128_CM_HMAC_SHA1_80` (the mandatory WebRTC profile) and
  `AEAD_AES_128_GCM` (RFC 7714). Both are real, both vector-tested.
- **Index handling per RFC 3711:** 48-bit index = ROC‖SEQ with §3.3.1 ROC estimation on receive
  (handles wrap in both directions), §3.3.2 replay windows, independent per-SSRC stream state so
  one context handles a whole rtcp-mux bundle direction. SRTCP keeps its own 31-bit index, E-bit
  always set, separate replay window.
- **`TryUnprotect*` never throws on wire data** — auth failure and replay return false. Tag
  comparison is `CryptographicOperations.FixedTimeEquals`. Protect/unprotect operate on spans
  with no per-packet allocation.
- AES-CM keystream generation reuses one ECB transform (no per-packet cipher construction).

## Testing

120 tests: RFC 3711 B.2 keystream and B.3 key-derivation vectors, RFC 7714 §16/§17 GCM vectors
(SRTP and SRTCP), protect→unprotect identity across sequence wrap with ROC transitions, tamper
and replay rejection, two-SSRC independence, and the RFC 5764 key-split helper.
