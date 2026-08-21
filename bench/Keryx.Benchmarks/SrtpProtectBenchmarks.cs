using System.Buffers.Binary;
using BenchmarkDotNet.Attributes;
using Keryx.Srtp;

namespace Keryx.Benchmarks;

/// <summary>
/// SRTP-protects a 1200-byte RTP packet with AES-128-CM / HMAC-SHA1-80, comparing Keryx's
/// <see cref="SrtpEncryptContext"/> against SIPSorcery's own (SharpSRTP-based, BouncyCastle-backed)
/// standalone SRTP implementation.
/// </summary>
/// <remarks>
/// <para>
/// <b>What each side measures.</b> Keryx: <see cref="SrtpEncryptContext.ProtectRtp"/>, constructed
/// from a <see cref="SrtpSessionKeys"/> master key/salt pair exactly as
/// <c>Keryx.Srtp.Tests.SrtpRoundTripTests</c> constructs it. SIPSorcery 10.x ships its own SRTP stack
/// under <c>SIPSorcery.Net.SharpSRTP.SRTP</c> (it no longer depends on Sipsorcery.Net's older
/// BouncyCastle-transform classes for this path); a standalone protect operation is reachable through
/// its public API without any DTLS/socket wiring via
/// <c>SrtpProtocol.CreateMasterKeys</c> → <c>SrtpProtocol.CreateSrtpSessionContext</c> →
/// <c>SrtpSessionContext.ProtectRtp</c>, using the <c>AES_CM_128_HMAC_SHA1_80</c> crypto suite
/// (SIPSorcery's <c>SrtpCryptoSuites</c> name for the same RFC 3711 profile Keryx calls
/// <see cref="SrtpProtectionProfileKind.Aes128CmHmacSha1_80"/>). Both sides are handed the identical
/// 30-byte master key‖salt material (16-byte key, 14-byte salt, split the same way for Keryx and
/// concatenated the same way for SIPSorcery), so they are protecting the same packet under the same
/// keys with the same cipher/MAC — this is a genuine like-for-like comparison, not an approximation.
/// </para>
/// <para>
/// <b>Sequence numbers</b> are incremented before every invocation on both sides so each call
/// protects a distinct, monotonically increasing sequence number, the way a real sender would; this
/// avoids exercising any same-index edge cases in either library's rollover-counter estimation. Since
/// this benchmark only protects (never unprotects), no SRTP replay-window rejection is in play either
/// way — protection is not the side that enforces replay.
/// </para>
/// <para>
/// <b>Allocation note.</b> Both <see cref="SrtpEncryptContext.ProtectRtp"/> and
/// <c>SrtpSessionContext.ProtectRtp</c> write into a caller-supplied output span and reuse internal
/// cipher/HMAC state across calls, so neither is expected to allocate materially on the hot path; the
/// <see cref="MemoryDiagnoser"/> output confirms (or refutes) that for both implementations.
/// </para>
/// </remarks>
[MemoryDiagnoser]
public class SrtpProtectBenchmarks
{
    private const int PacketSize = 1200;
    private const uint Ssrc = 0xABCD1234;
    private const byte PayloadType = 96;

    private readonly byte[] _packet = new byte[PacketSize];
    private ushort _sequenceNumber;

    private SrtpEncryptContext _keryxContext = null!;
    private byte[] _keryxOutput = [];

    private SIPSorcery.Net.SharpSRTP.SRTP.SrtpSessionContext _sipSorceryContext = null!;
    private byte[] _sipSorceryOutput = [];

    [GlobalSetup]
    public void Setup()
    {
        // Identical 30-byte master key‖salt material for both sides (16-byte key, 14-byte salt —
        // the AES-128-CM / HMAC-SHA1-80 sizes per RFC 3711).
        var combined = new byte[16 + 14];
        new Random(20260821).NextBytes(combined);
        var masterKey = combined.AsSpan(0, 16).ToArray();
        var masterSalt = combined.AsSpan(16, 14).ToArray();

        var keryxProfile = SrtpProtectionProfile.Aes128CmHmacSha1_80;
        var keryxKeys = new SrtpSessionKeys(masterKey, masterSalt);
        _keryxContext = new SrtpEncryptContext(keryxProfile, keryxKeys);
        _keryxOutput = new byte[PacketSize + keryxProfile.RtpOverhead];

        var sipSorceryKeys = new SIPSorcery.Net.SharpSRTP.SRTP.SrtpKeys(
            SIPSorcery.Net.SharpSRTP.SRTP.SrtpProtocol.SrtpCryptoSuites[
                SIPSorcery.Net.SharpSRTP.SRTP.SrtpCryptoSuites.AES_CM_128_HMAC_SHA1_80],
            combined);
        _sipSorceryContext = SIPSorcery.Net.SharpSRTP.SRTP.SrtpProtocol.CreateSrtpSessionContext(sipSorceryKeys);
        _sipSorceryOutput = new byte[_sipSorceryContext.CalculateRequiredSrtpPayloadLength(PacketSize)];

        // A well-formed 12-byte-header RTP packet (V=2, no padding/extension/CSRC), fixed SSRC,
        // random payload filling it out to exactly 1200 bytes; the sequence number is overwritten
        // before every protect call below.
        _packet[0] = 0x80;
        _packet[1] = PayloadType;
        BinaryPrimitives.WriteUInt32BigEndian(_packet.AsSpan(4, 4), 90_000);
        BinaryPrimitives.WriteUInt32BigEndian(_packet.AsSpan(8, 4), Ssrc);
        new Random(7).NextBytes(_packet.AsSpan(12));
    }

    /// <summary>Keryx: <see cref="SrtpEncryptContext.ProtectRtp"/>.</summary>
    /// <returns>The number of bytes written, so the call cannot be dead-code eliminated.</returns>
    [Benchmark(Baseline = true)]
    public int Keryx_ProtectRtp()
    {
        _sequenceNumber++;
        BinaryPrimitives.WriteUInt16BigEndian(_packet.AsSpan(2, 2), _sequenceNumber);
        return _keryxContext.ProtectRtp(_packet, _keryxOutput);
    }

    /// <summary>SIPSorcery: <c>SrtpSessionContext.ProtectRtp</c> (SharpSRTP, AES_CM_128_HMAC_SHA1_80).</summary>
    /// <returns>The number of bytes written, so the call cannot be dead-code eliminated.</returns>
    [Benchmark]
    public int SipSorcery_ProtectRtp()
    {
        _sequenceNumber++;
        BinaryPrimitives.WriteUInt16BigEndian(_packet.AsSpan(2, 2), _sequenceNumber);
        _sipSorceryContext.ProtectRtp(_packet, _sipSorceryOutput, out var bytesWritten);
        return bytesWritten;
    }

    [GlobalCleanup]
    public void Cleanup() => _keryxContext.Dispose();
}
