using BenchmarkDotNet.Attributes;
using Keryx.Rtp;
using Keryx.Rtp.Simulcast;

namespace Keryx.Benchmarks;

/// <summary>
/// The SFU fan-out rewrite primitive: <see cref="RtpForwarder.TryForward"/> stamps one ingested
/// packet with a subscriber's SSRC and contiguous sequence/timestamp numbering before it is
/// re-encrypted. It runs once per subscriber per packet, so its per-packet cost sits alongside the
/// SRTP encrypt in the fan-out budget.
/// </summary>
[MemoryDiagnoser]
public class ForwardBenchmarks
{
    private const uint OutboundSsrc = 0xF00D_F00D;
    private const uint UpstreamSsrc = 0x1111_2222;

    private readonly RtpForwarder _forwarder = new(OutboundSsrc);
    private SimulcastLayerId _layer;
    private byte[] _payload = null!;
    private byte[] _destination = null!;
    private ushort _seq;
    private uint _timestamp;

    [GlobalSetup]
    public void Setup()
    {
        _layer = SimulcastLayerId.Parse("hi");
        _payload = new byte[BenchPackets.VideoPacketSize - BenchPackets.HeaderLength];
        _destination = new byte[BenchPackets.VideoPacketSize + 64];
        _seq = 1000;
        _timestamp = 90_000;

        // Promote the desired layer to active on a keyframe so steady-state forwards take the hot path.
        _forwarder.SelectLayer(_layer);
        var header = BuildHeader(_seq, _timestamp);
        var classification = new RtpLayerClassification(_layer, UpstreamSsrc, IsRepair: false, RtpLayerClassificationSource.RidExtension);
        _forwarder.TryForward(classification, header, _payload, canStartLayer: true, _destination, out _);
        _seq++;
        _timestamp += 3000;
    }

    /// <summary>Rewrite one steady-state media packet for a subscriber.</summary>
    [Benchmark(Description = "RtpForwarder.TryForward (per-subscriber rewrite)")]
    public int TryForward()
    {
        var header = BuildHeader(_seq++, _timestamp);
        _timestamp += 3000;
        var classification = new RtpLayerClassification(_layer, UpstreamSsrc, IsRepair: false, RtpLayerClassificationSource.RidExtension);
        _forwarder.TryForward(classification, header, _payload, canStartLayer: false, _destination, out var written);
        return written;
    }

    private static RtpHeader BuildHeader(ushort sequenceNumber, uint timestamp) => new()
    {
        Version = 2,
        PayloadType = BenchPackets.VideoPayloadType,
        Ssrc = UpstreamSsrc,
        SequenceNumber = sequenceNumber,
        Timestamp = timestamp,
        Marker = false,
    };
}
