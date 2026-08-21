using BenchmarkDotNet.Attributes;
using Keryx.Rtp.Packetization;

namespace Keryx.Benchmarks;

/// <summary>
/// Packetizes one realistic H.264 Annex B access unit (SPS + PPS + a 25 KB IDR slice) into RTP
/// payloads at a 1200-byte MTU, comparing Keryx's <see cref="H264Packetizer"/> against SIPSorcery's
/// H.264 send path.
/// </summary>
/// <remarks>
/// <para>
/// <b>What each side measures.</b> Keryx: <see cref="H264Packetizer.Packetize"/> writing straight
/// into a reused scratch buffer via <see cref="IRtpPayloadWriter"/> — the zero-copy "pooled packet
/// buffer" pattern the interface's own documentation describes as the intended production usage.
/// SIPSorcery: there is no standalone, sendable-free H.264 packetizer in its public API —
/// <c>VideoStream.SendH264Frame</c> is an instance method on a class that requires a wired-up
/// <c>RTPSession</c> (sockets, SDP negotiation, etc.), which is out of scope for a microbenchmark.
/// Its packetization logic is reproduced here from <c>VideoStream.SendH26XNal</c> (decompiled from
/// SIPSorcery.dll 10.0.16) using only the public building blocks it itself calls:
/// <c>H264Packetiser.ParseNals</c> to split the access unit into NAL units, and
/// <c>H264Packetiser.GetH264RtpHeader</c> to build FU-A headers. This mirrors SIPSorcery's actual
/// send-path allocation and copy pattern, including its choices, faithfully:
/// </para>
/// <list type="bullet">
/// <item>SIPSorcery never aggregates NAL units into STAP-A packets — every NAL at or under 1200
/// bytes (i.e. the SPS and the PPS here) is sent as its own single-NAL-unit RTP packet. Keryx's
/// packetizer does aggregate small NALs into a STAP-A when that saves a packet (RFC 6184 §5.7.1), so
/// it emits one fewer packet for the SPS+PPS pair than SIPSorcery does. This is a genuine behavioral
/// difference between the two packetizers, not a benchmark bug — both packet counts are reported.</item>
/// <item>SIPSorcery's FU-A fragmentation uses a fixed 1200-byte chunk size for the fragment body and
/// then prepends its 2-byte FU-A header, so its largest FU-A packets are 1202 bytes on the wire —
/// slightly over the nominal 1200-byte MTU. Keryx's packetizer treats <c>maxPayloadSize</c> as a hard
/// ceiling on the whole RTP payload (FU-A header included), so its largest fragment is exactly 1200
/// bytes. This is an observation about SIPSorcery's public packetizer, not something this benchmark
/// suite fixes.</item>
/// <item>SIPSorcery's <c>ParseNals</c> allocates a fresh <c>byte[]</c> per NAL unit (via
/// <c>Span.ToArray()</c>), and its single-NAL and FU-A paths each allocate a fresh <c>byte[]</c> per
/// RTP packet — that is simply what its public API surface does. Keryx's packetizer writes into the
/// caller-supplied buffer with zero allocation on the hot path. The <see cref="MemoryDiagnoser"/>
/// output reflects this real difference in each library's public API, not an artificially rigged
/// comparison.</item>
/// </list>
/// <para>
/// Both benchmark methods return the RTP packet count produced for the access unit, which
/// BenchmarkDotNet keeps alive as the method's result (preventing dead-code elimination) and which
/// also serves as the sanity check mentioned in the task: the counts are printed once during
/// <see cref="Setup"/>.
/// </para>
/// </remarks>
[MemoryDiagnoser]
public class H264PacketizationBenchmarks
{
    private const int Mtu = 1200;

    private readonly H264Packetizer _packetizer = new();
    private readonly ScratchPayloadWriter _writer = new(Mtu);

    private byte[] _accessUnit = [];

    /// <summary>Builds the synthetic Annex B access unit once for every invocation to packetize.</summary>
    [GlobalSetup]
    public void Setup()
    {
        var random = new Random(20260821);

        // SPS: NAL header 0x67 (forbidden=0, nal_ref_idc=3, type=7) + ~29 bytes of payload.
        var sps = BuildNal(0x67, 29, random);

        // PPS: NAL header 0x68 (nal_ref_idc=3, type=8) + ~7 bytes of payload.
        var pps = BuildNal(0x68, 7, random);

        // IDR slice: NAL header 0x65 (nal_ref_idc=3, type=5) + a ~25 KB slice payload.
        var idr = BuildNal(0x65, (25 * 1024) - 1, random);

        var au = new byte[
            AnnexB.FourByteStartCode.Length + sps.Length +
            AnnexB.FourByteStartCode.Length + pps.Length +
            AnnexB.FourByteStartCode.Length + idr.Length];

        var offset = 0;
        offset = AppendStartCodeAndNal(au, offset, sps);
        offset = AppendStartCodeAndNal(au, offset, pps);
        AppendStartCodeAndNal(au, offset, idr);

        _accessUnit = au;

        var keryxPackets = _packetizer.Packetize(_accessUnit, Mtu, _writer);
        var sipSorceryPackets = SipSorceryPacketize(_accessUnit, out _);
        Console.WriteLine(
            $"[H264PacketizationBenchmarks] access unit = {_accessUnit.Length:N0} bytes; "
            + $"Keryx packets = {keryxPackets}; SIPSorcery-equivalent packets = {sipSorceryPackets}.");
    }

    /// <summary>Keryx: <see cref="H264Packetizer.Packetize"/> into a reused pooled payload buffer.</summary>
    /// <returns>The number of RTP packets produced.</returns>
    [Benchmark(Baseline = true)]
    public int Keryx_Packetize() => _packetizer.Packetize(_accessUnit, Mtu, _writer);

    /// <summary>
    /// SIPSorcery: <c>H264Packetiser.ParseNals</c> + <c>H264Packetiser.GetH264RtpHeader</c>, mirroring
    /// <c>VideoStream.SendH26XNal</c>'s per-NAL single-packet / FU-A fragmentation exactly.
    /// </summary>
    /// <returns>The number of RTP packets produced.</returns>
    [Benchmark]
    public int SipSorcery_Packetize() => SipSorceryPacketize(_accessUnit, out _);

    private static byte[] BuildNal(byte header, int payloadLength, Random random)
    {
        var nal = new byte[1 + payloadLength];
        nal[0] = header;
        // Non-zero random bytes only: guarantees no two-byte or three-byte run can be mistaken for
        // an Annex B start code ("emulation-prevention-free" payload, as the task specifies), so the
        // access unit always parses back into exactly three NAL units.
        for (var i = 1; i < nal.Length; i++)
        {
            nal[i] = (byte)random.Next(1, 256);
        }

        return nal;
    }

    private static int AppendStartCodeAndNal(byte[] destination, int offset, byte[] nal)
    {
        AnnexB.FourByteStartCode.CopyTo(destination.AsSpan(offset));
        offset += AnnexB.FourByteStartCode.Length;
        nal.CopyTo(destination.AsSpan(offset));
        return offset + nal.Length;
    }

    /// <summary>
    /// Reproduces SIPSorcery's <c>VideoStream.SendH26XNal</c> (SIPSorcery.dll 10.0.16, decompiled)
    /// using only its public building blocks, without needing a wired-up <c>RTPSession</c>.
    /// </summary>
    private static int SipSorceryPacketize(byte[] accessUnit, out long totalPayloadBytes)
    {
        var packets = 0;
        long total = 0;

        foreach (var nal in SIPSorcery.Net.H264Packetiser.ParseNals(accessUnit))
        {
            var data = nal.NAL;
            if (data.Length <= Mtu)
            {
                // Single NAL unit packet (RFC 6184 §5.6): SIPSorcery copies the whole NAL, header
                // byte included, into a fresh packet-sized array.
                var packet = new byte[data.Length];
                Buffer.BlockCopy(data, 0, packet, 0, data.Length);
                packets++;
                total += packet.Length;
                continue;
            }

            // FU-A fragmentation (RFC 6184 §5.8): fixed 1200-byte body chunks, each with its own
            // freshly allocated 2-byte FU-A header prepended.
            var header0 = data[0];
            var bodyLength = data.Length - 1;
            var position = 0;
            while (position < bodyLength)
            {
                var chunk = Math.Min(Mtu, bodyLength - position);
                var isFirst = position == 0;
                var isLast = position + chunk == bodyLength;
                var fuHeader = SIPSorcery.Net.H264Packetiser.GetH264RtpHeader(header0, isFirst, isLast);

                var packet = new byte[chunk + fuHeader.Length];
                Buffer.BlockCopy(fuHeader, 0, packet, 0, fuHeader.Length);
                Buffer.BlockCopy(data, 1 + position, packet, fuHeader.Length, chunk);

                packets++;
                total += packet.Length;
                position += chunk;
            }
        }

        totalPayloadBytes = total;
        return packets;
    }

    /// <summary>
    /// An <see cref="IRtpPayloadWriter"/> that writes every payload into one reused buffer, the way a
    /// real sender writes straight into a pooled outbound packet buffer before handing it to SRTP.
    /// Commit tracks a running byte total so the JIT cannot prove the writes are unobserved.
    /// </summary>
    private sealed class ScratchPayloadWriter(int capacity) : IRtpPayloadWriter
    {
        private readonly byte[] _scratch = new byte[capacity];

        /// <summary>Running total of committed payload bytes; read by nothing but keeps writes live.</summary>
        public long TotalBytes { get; private set; }

        public Span<byte> GetPayloadBuffer(int sizeHint) => _scratch;

        public void Commit(int length, bool marker) => TotalBytes += length;
    }
}
