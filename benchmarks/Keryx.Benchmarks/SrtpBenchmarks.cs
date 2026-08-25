using System.Buffers.Binary;
using BenchmarkDotNet.Attributes;
using Keryx.Srtp;

namespace Keryx.Benchmarks;

/// <summary>
/// The headline numbers for SFU fan-out: per-packet SRTP protect (encrypt) and unprotect (decrypt)
/// throughput at ~1200-byte packets. In a broadcast SFU each subscriber gets the same media
/// re-encrypted under its own SRTP context, so the protect rate is the primary driver of
/// subscribers-per-core.
/// </summary>
/// <remarks>
/// Two encrypt figures are reported per profile: the realistic per-subscriber path through
/// <see cref="SrtpEncryptContext.ProtectRtp"/> (header parse + rollover bookkeeping + AEAD), and the
/// pure-crypto floor through the internal transform. Decrypt is measured at the transform layer so
/// the replay window does not reject the repeated packet — it isolates the crypto cost the receive
/// path pays once per ingested packet.
/// </remarks>
[MemoryDiagnoser]
public class SrtpBenchmarks
{
    /// <summary>DTLS-SRTP protection profile under test.</summary>
    [Params("AeadAes128Gcm", "AeadAes256Gcm", "Aes128CmHmacSha1_80")]
    public string Profile { get; set; } = "AeadAes128Gcm";

    private SrtpProtectionProfile _profile = null!;
    private SrtpEncryptContext _encryptContext = null!;
    private ISrtpTransform _transform = null!;

    private byte[] _plaintext = null!;
    private byte[] _encryptOutput = null!;
    private byte[] _protectedPacket = null!;
    private byte[] _decryptOutput = null!;
    private int _protectedLength;
    private ushort _seq;

    private const uint Ssrc = 0x1234_5678;

    [GlobalSetup]
    public void Setup()
    {
        _profile = Profile switch
        {
            "AeadAes128Gcm" => SrtpProtectionProfile.AeadAes128Gcm,
            "AeadAes256Gcm" => SrtpProtectionProfile.AeadAes256Gcm,
            "Aes128CmHmacSha1_80" => SrtpProtectionProfile.Aes128CmHmacSha1_80,
            _ => throw new ArgumentOutOfRangeException(nameof(Profile)),
        };

        var keys = BenchPackets.NewKeys(_profile);
        _encryptContext = new SrtpEncryptContext(_profile, keys);
        // Same keying material through the internal transform for the pure-crypto measurements.
        _transform = SrtpTransformFactory.Create(_profile, keys);

        _plaintext = BenchPackets.BuildRtpPacket(Ssrc, sequenceNumber: 0, timestamp: 90_000, BenchPackets.VideoPacketSize);
        _encryptOutput = new byte[BenchPackets.VideoPacketSize + _profile.RtpOverhead];

        // Pre-encrypt one packet the decrypt benchmark unprotects repeatedly (transform layer, so the
        // replay window is not in the loop).
        _protectedPacket = new byte[BenchPackets.VideoPacketSize + _profile.RtpOverhead];
        _protectedLength = _transform.ProtectRtp(
            _plaintext, BenchPackets.HeaderLength, Ssrc, rolloverCounter: 0, sequenceNumber: 0, _protectedPacket);
        _decryptOutput = new byte[_protectedPacket.Length];
        _seq = 1;
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _encryptContext.Dispose();
        _transform.Dispose();
    }

    /// <summary>
    /// The real per-subscriber encrypt path. The sequence number is advanced every call because the
    /// encrypt context refuses a reused packet index (nonce-reuse guard), which mirrors a live stream.
    /// </summary>
    [Benchmark(Description = "Encrypt (SrtpEncryptContext.ProtectRtp, per-subscriber path)")]
    public int EncryptContext()
    {
        BinaryPrimitives.WriteUInt16BigEndian(_plaintext.AsSpan(2, 2), _seq++);
        return _encryptContext.ProtectRtp(_plaintext, _encryptOutput);
    }

    /// <summary>Pure AEAD/cipher encrypt cost with no context bookkeeping.</summary>
    [Benchmark(Description = "Encrypt (transform, pure crypto)")]
    public int EncryptTransform() =>
        _transform.ProtectRtp(_plaintext, BenchPackets.HeaderLength, Ssrc, rolloverCounter: 0, sequenceNumber: 0, _encryptOutput);

    /// <summary>Pure AEAD/cipher decrypt + tag verification cost.</summary>
    [Benchmark(Description = "Decrypt (transform, pure crypto)")]
    public bool DecryptTransform() =>
        _transform.TryUnprotectRtp(
            _protectedPacket.AsSpan(0, _protectedLength),
            BenchPackets.HeaderLength,
            Ssrc,
            rolloverCounter: 0,
            sequenceNumber: 0,
            _decryptOutput,
            out _);
}
