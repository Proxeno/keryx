using BenchmarkDotNet.Attributes;

namespace Keryx.Benchmarks;

/// <summary>
/// Serializes a plain 12-byte RTP header (no CSRC list, no header extension) and parses it straight
/// back, comparing Keryx's <see cref="Keryx.Rtp.RtpHeader"/> against SIPSorcery's
/// <see cref="SIPSorcery.Net.RTPHeader"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>What each side measures.</b> Both benchmark methods do the same two things per invocation:
/// bump the sequence number, serialize a header, then parse the serialized bytes back. Keryx:
/// <see cref="Keryx.Rtp.RtpHeader.WriteTo"/> into a reused 12-byte buffer, then
/// <see cref="Keryx.Rtp.RtpHeader.TryParse"/> from that same buffer. SIPSorcery:
/// <see cref="SIPSorcery.Net.RTPHeader.GetBytes"/>, then <c>new RTPHeader(byte[])</c> on the result.
/// </para>
/// <para>
/// <b>Parity note.</b> <see cref="Keryx.Rtp.RtpHeader"/> is a <c>ref struct</c> built fresh from
/// scalar fields on every call — that is its only supported construction path, and it costs nothing
/// but stack space. <see cref="SIPSorcery.Net.RTPHeader"/> is a class; its parameterless constructor
/// also draws three values from a CSPRNG (<c>Crypto.GetRandomUInt16/GetRandomUInt</c>), which is
/// unrelated to header serialization and would dominate a per-invocation allocation-vs-crypto
/// comparison. To keep the benchmark measuring what it says it measures (serialize + parse), the
/// <see cref="SIPSorcery.Net.RTPHeader"/> instance is created once in <see cref="Setup"/> and its
/// fields are reused/overwritten per invocation, exactly as a long-lived sender would. Both sides
/// still allocate on every call where their own public API forces it: <c>GetBytes()</c> allocates a
/// fresh <c>byte[12]</c> and <c>new RTPHeader(byte[])</c> allocates the header object itself; Keryx's
/// <c>WriteTo</c>/<c>TryParse</c> allocate nothing. That is a real, honestly measured difference
/// between a <c>ref struct</c> view over caller-owned memory and a heap-allocated header class, not an
/// artifact of how this benchmark is wired.
/// </para>
/// </remarks>
[MemoryDiagnoser]
public class RtpHeaderBenchmarks
{
    private const byte PayloadType = 96;
    private const uint Ssrc = 0x11223344;
    private const uint Timestamp = 3_000;

    private readonly byte[] _buffer = new byte[Keryx.Rtp.RtpHeader.FixedLength];
    private SIPSorcery.Net.RTPHeader _sipSorceryHeader = null!;
    private ushort _sequenceNumber;

    [GlobalSetup]
    public void Setup()
    {
        _sipSorceryHeader = new SIPSorcery.Net.RTPHeader
        {
            Version = SIPSorcery.Net.RTPHeader.RTP_VERSION,
            PaddingFlag = 0,
            HeaderExtensionFlag = 0,
            CSRCCount = 0,
            MarkerBit = 0,
            PayloadType = PayloadType,
            Timestamp = Timestamp,
            SyncSource = Ssrc,
        };
    }

    /// <summary>Keryx: <see cref="Keryx.Rtp.RtpHeader.WriteTo"/> then <see cref="Keryx.Rtp.RtpHeader.TryParse"/>.</summary>
    /// <returns>The parsed sequence number, so the round trip cannot be dead-code eliminated.</returns>
    [Benchmark(Baseline = true)]
    public int Keryx_WriteThenParse()
    {
        _sequenceNumber++;

        var header = new Keryx.Rtp.RtpHeader
        {
            Version = Keryx.Rtp.RtpHeader.SupportedVersion,
            Marker = false,
            PayloadType = PayloadType,
            SequenceNumber = _sequenceNumber,
            Timestamp = Timestamp,
            Ssrc = Ssrc,
        };

        header.WriteTo(_buffer);
        Keryx.Rtp.RtpHeader.TryParse(_buffer, out var parsed);
        return parsed.SequenceNumber;
    }

    /// <summary>SIPSorcery: <see cref="SIPSorcery.Net.RTPHeader.GetBytes"/> then <c>new RTPHeader(byte[])</c>.</summary>
    /// <returns>The parsed sequence number, so the round trip cannot be dead-code eliminated.</returns>
    [Benchmark]
    public int SipSorcery_WriteThenParse()
    {
        _sequenceNumber++;
        _sipSorceryHeader.SequenceNumber = _sequenceNumber;

        var bytes = _sipSorceryHeader.GetBytes();
        var parsed = new SIPSorcery.Net.RTPHeader(bytes);
        return parsed.SequenceNumber;
    }
}
