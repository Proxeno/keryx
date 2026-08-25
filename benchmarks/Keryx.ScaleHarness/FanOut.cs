using System.Security.Cryptography;
using Keryx.Rtp;
using Keryx.Rtp.Simulcast;
using Keryx.Srtp;

namespace Keryx.ScaleHarness;

/// <summary>
/// One SFU fan-out path: the per-subscriber state and per-packet work a broadcast server does for
/// every viewer — rewrite the ingested packet onto the subscriber's SSRC/sequence space
/// (<see cref="RtpForwarder"/>) and re-encrypt it under that subscriber's own SRTP context. This is
/// the embarrassingly-parallel work whose rate sets the subscriber ceiling.
/// </summary>
internal sealed class FanOutPath : IDisposable
{
    private readonly RtpForwarder _forwarder;
    private readonly SrtpEncryptContext _srtp;
    private readonly SimulcastLayerId _layer;
    private readonly byte[] _forwardDest;
    private readonly byte[] _encryptOut;

    public FanOutPath(uint outboundSsrc, SrtpProtectionProfile profile)
    {
        _forwarder = new RtpForwarder(outboundSsrc);
        _layer = SimulcastLayerId.Parse("hi");
        _forwarder.SelectLayer(_layer);

        var key = new byte[profile.MasterKeyLength];
        var salt = new byte[profile.MasterSaltLength];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(salt);
        _srtp = new SrtpEncryptContext(profile, new SrtpSessionKeys(key, salt));

        _forwardDest = new byte[Ingest.PacketSize + 64];
        _encryptOut = new byte[Ingest.PacketSize + 64 + profile.RtpOverhead];
    }

    /// <summary>Primes the forwarder's active layer with a keyframe so steady packets take the hot path.</summary>
    public void Warm(uint upstreamSsrc)
    {
        var header = Ingest.Header(upstreamSsrc, sequenceNumber: 0, timestamp: 0);
        var classification = new RtpLayerClassification(_layer, upstreamSsrc, IsRepair: false, RtpLayerClassificationSource.RidExtension);
        if (_forwarder.TryForward(classification, header, Ingest.Payload, canStartLayer: true, _forwardDest, out var written) == RtpForwardResult.Forwarded)
        {
            _srtp.ProtectRtp(_forwardDest.AsSpan(0, written), _encryptOut);
        }
    }

    /// <summary>Forward-rewrite and re-encrypt one ingested packet for this subscriber.</summary>
    /// <returns>True when the packet was forwarded and encrypted.</returns>
    public bool ProcessOne(uint upstreamSsrc, ushort sequenceNumber, uint timestamp)
    {
        var header = Ingest.Header(upstreamSsrc, sequenceNumber, timestamp);
        var classification = new RtpLayerClassification(_layer, upstreamSsrc, IsRepair: false, RtpLayerClassificationSource.RidExtension);
        if (_forwarder.TryForward(classification, header, Ingest.Payload, canStartLayer: false, _forwardDest, out var written) != RtpForwardResult.Forwarded)
        {
            return false;
        }

        _srtp.ProtectRtp(_forwardDest.AsSpan(0, written), _encryptOut);
        return true;
    }

    public void Dispose() => _srtp.Dispose();
}

/// <summary>The single ingest stream every fan-out path re-encrypts: a fixed synthetic 720p packet.</summary>
internal static class Ingest
{
    public const int PacketSize = 1200;
    public const int HeaderLength = 12;
    public const byte VideoPayloadType = 96;

    /// <summary>The RTP payload bytes shared by every ingested packet (content is irrelevant to cost).</summary>
    public static readonly byte[] Payload = BuildPayload();

    public static RtpHeader Header(uint ssrc, ushort sequenceNumber, uint timestamp) => new()
    {
        Version = 2,
        PayloadType = VideoPayloadType,
        Ssrc = ssrc,
        SequenceNumber = sequenceNumber,
        Timestamp = timestamp,
        Marker = false,
    };

    private static byte[] BuildPayload()
    {
        var payload = new byte[PacketSize - HeaderLength];
        RandomNumberGenerator.Fill(payload);
        return payload;
    }
}
