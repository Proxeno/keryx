using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using Keryx.Rtp.Packetization;

namespace Keryx.Benchmarks;

/// <summary>
/// The send-side packetization primitive: turning one encoded H.264 access unit into RTP payloads.
/// A source ingesting into the SFU packetizes once per frame (~30 fps); a 720p 2 Mbps P-frame is a
/// single large slice NAL that fragments into ~7 FU-A packets. The packetizer is documented as
/// allocation-free on this path, which the memory column confirms.
/// </summary>
[MemoryDiagnoser]
public class PacketizeBenchmarks
{
    /// <summary>Path MTU (1200) minus IP/UDP/RTP header and the 16-byte GCM tag.</summary>
    private const int MaxPayloadSize = 1200 - 40 - 12 - 16;

    private readonly H264Packetizer _packetizer = new();
    private readonly ReusablePayloadWriter _writer = new();

    private byte[] _pFrame = null!;
    private byte[] _keyFrame = null!;

    [GlobalSetup]
    public void Setup()
    {
        // A 720p 2 Mbps stream at 30 fps averages ~8.3 KB per frame; a P-frame is one coded slice.
        _pFrame = BuildAnnexBFrame(sliceType: 1, sliceLength: 8300, includeParameterSets: false);
        // A keyframe carries SPS + PPS ahead of a larger IDR slice.
        _keyFrame = BuildAnnexBFrame(sliceType: 5, sliceLength: 22000, includeParameterSets: true);
    }

    /// <summary>Packetize a steady-state P-frame (the ~250 pps common case).</summary>
    [Benchmark(Description = "Packetize 720p P-frame (FU-A fragmentation)")]
    public int PacketizePFrame() => _packetizer.Packetize(_pFrame, rtpTimestamp: 90_000, MaxPayloadSize, _writer);

    /// <summary>Packetize a keyframe with parameter-set aggregation.</summary>
    [Benchmark(Description = "Packetize 720p keyframe (STAP-A + FU-A)")]
    public int PacketizeKeyFrame() => _packetizer.Packetize(_keyFrame, rtpTimestamp: 90_000, MaxPayloadSize, _writer);

    private static byte[] BuildAnnexBFrame(byte sliceType, int sliceLength, bool includeParameterSets)
    {
        var units = new List<byte[]>();
        if (includeParameterSets)
        {
            units.Add(BuildNalUnit(H264NalUnitType.SequenceParameterSet, 20));
            units.Add(BuildNalUnit(H264NalUnitType.PictureParameterSet, 8));
        }

        units.Add(BuildNalUnit(sliceType, sliceLength));

        var total = 0;
        foreach (var unit in units)
        {
            total += 4 + unit.Length; // 4-byte Annex B start code per NAL unit.
        }

        var frame = new byte[total];
        var offset = 0;
        foreach (var unit in units)
        {
            frame[offset + 2] = 0x00;
            frame[offset + 3] = 0x01; // 00 00 00 01 start code.
            offset += 4;
            unit.CopyTo(frame.AsSpan(offset));
            offset += unit.Length;
        }

        return frame;
    }

    private static byte[] BuildNalUnit(byte type, int length)
    {
        var unit = new byte[length];
        RandomNumberGenerator.Fill(unit);
        unit[0] = (byte)(0x40 | (type & 0x1F)); // nri=2, forbidden=0.
        return unit;
    }
}

/// <summary>
/// An <see cref="IRtpPayloadWriter"/> that hands out slices of one reusable buffer and never
/// allocates, so the packetizer's own allocation profile is what the memory diagnoser records.
/// </summary>
internal sealed class ReusablePayloadWriter : IRtpPayloadWriter
{
    private byte[] _buffer = new byte[1500];

    /// <summary>Number of payloads committed since the last packetize call — read by the benchmark host.</summary>
    public int Count { get; private set; }

    public Span<byte> GetPayloadBuffer(int sizeHint)
    {
        if (_buffer.Length < sizeHint)
        {
            _buffer = new byte[sizeHint];
        }

        return _buffer;
    }

    public void Commit(int length, bool marker) => Count++;
}
