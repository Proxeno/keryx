using System.Buffers.Binary;
using System.Net;
using BenchmarkDotNet.Attributes;
using Keryx;
using Keryx.Core;
using Keryx.Rtp;
using Keryx.Sdp;

namespace Keryx.Benchmarks;

/// <summary>
/// The post-SRTP receive path a single ingest source drives: <c>ProcessDecryptedRtp</c> parses the
/// packet, records transport-wide-cc and abs-send-time arrival, demuxes the route, and delivers to
/// the handler. In a broadcast SFU this runs once per ingested packet (not per subscriber), but its
/// allocation profile matters — the memory column confirms the steady-state receive path allocates
/// ~nothing per packet after the recent GC work (RemoteSsrc boxing, RID string, RTCP arrays).
/// </summary>
[MemoryDiagnoser]
public class ReceivePathBenchmarks
{
    private const byte VideoPayloadType = 96;
    private const uint MediaSsrc = 3204773231u;

    private PeerConnection _receiver = null!;
    private byte[] _packet = null!;
    private ushort _seq;

    [GlobalSetup]
    public void Setup()
    {
        var config = new PeerConnectionConfig
        {
            BindAddress = IPAddress.Loopback,
            Logger = NullLogger.Instance,
        };
        _receiver = new PeerConnection(config);
        _receiver.SetRemoteDescriptionAsync(RemoteOffer, SdpType.Offer, CancellationToken.None)
            .GetAwaiter().GetResult();

        // An attached (empty) handler keeps the delivery branch on the hot path it would take live.
        _receiver.OnRtpPacketReceived += static (in RtpPacketInfo info, ReadOnlySpan<byte> payload) => { };

        _packet = BuildVideoPacket(MediaSsrc, sequenceNumber: 1000);
        _seq = 1000;
    }

    [GlobalCleanup]
    public void Cleanup() => _receiver.DisposeAsync().AsTask().GetAwaiter().GetResult();

    /// <summary>Drive one decrypted media packet through the full post-SRTP receive path.</summary>
    [Benchmark(Description = "ProcessDecryptedRtp (single-ingest receive path)")]
    public void ProcessDecryptedRtp()
    {
        // Advance the sequence number so the packet is a fresh in-order arrival for the tracked stream
        // rather than a replay, matching a live ingest.
        BinaryPrimitives.WriteUInt16BigEndian(_packet.AsSpan(2, 2), _seq++);
        _receiver.DeliverDecryptedRtpForTest(_packet);
    }

    private static byte[] BuildVideoPacket(uint ssrc, ushort sequenceNumber)
    {
        var header = new RtpHeader
        {
            Version = 2,
            PayloadType = VideoPayloadType,
            Ssrc = ssrc,
            SequenceNumber = sequenceNumber,
            Timestamp = 90000u,
            Marker = true,
        };

        var payload = new byte[] { 0x01, 0xAA, 0xBB, 0xCC };
        var packet = new byte[RtpHeader.FixedLength + payload.Length];
        var written = header.WriteTo(packet);
        payload.CopyTo(packet.AsSpan(written));
        return packet;
    }

    private static readonly string RemoteOffer = string.Join("\r\n",
        "v=0",
        "o=- 4611731400430051336 2 IN IP4 127.0.0.1",
        "s=-",
        "t=0 0",
        "a=group:BUNDLE 0 1",
        "a=extmap-allow-mixed",
        "a=msid-semantic: WMS stream",
        "m=audio 9 UDP/TLS/RTP/SAVPF 111",
        "c=IN IP4 0.0.0.0",
        "a=rtcp:9 IN IP4 0.0.0.0",
        "a=ice-ufrag:hT7a",
        "a=ice-pwd:XKQVjJ9wRVWy3zNsL6mQ0pTb",
        "a=ice-options:trickle",
        "a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24",
        "a=setup:actpass",
        "a=mid:0",
        "a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid",
        "a=sendrecv",
        "a=rtcp-mux",
        "a=rtpmap:111 opus/48000/2",
        "a=ssrc:1657320245 cname:JnQ3z0",
        "m=video 9 UDP/TLS/RTP/SAVPF 96",
        "c=IN IP4 0.0.0.0",
        "a=rtcp:9 IN IP4 0.0.0.0",
        "a=ice-ufrag:hT7a",
        "a=ice-pwd:XKQVjJ9wRVWy3zNsL6mQ0pTb",
        "a=ice-options:trickle",
        "a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24",
        "a=setup:actpass",
        "a=mid:1",
        "a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid",
        "a=sendrecv",
        "a=rtcp-mux",
        "a=rtpmap:96 H264/90000",
        "a=rtcp-fb:96 nack",
        "a=ssrc:3204773231 cname:JnQ3z0",
        "");
}
