using System.Buffers.Binary;
using System.Security.Cryptography;
using Keryx.Rtp;

namespace Keryx.BroadcastLoadTest;

/// <summary>
/// One synthetic ingest media profile: the packet size and per-viewer packet rate a broadcaster pushes
/// for a given resolution. These are the harness models from <c>broadcast-scale.md</c> §1.1 — a 720p
/// H.264 stream is ~2 Mbps at ~300 video pkt/s (~1200 B on the wire), a 480p stream ~1 Mbps at ~200
/// pkt/s (~900 B). Opus audio adds ~50 pkt/s of tiny (~120 B) packets, a ~17% packet-rate premium on a
/// negligible byte budget; the video packet rate is what the fan-out ceiling is measured against, so the
/// per-viewer rate below is the video rate and the audio premium is reported separately.
/// </summary>
internal sealed record MediaProfile(string Name, int VideoPacketBytes, int VideoPacketsPerSecond, double MegabitsPerSecond)
{
    /// <summary>720p H.264, ~2 Mbps, ~30 fps: ~300 video pkt/s at ~1200 B/packet.</summary>
    public static readonly MediaProfile Video720p = new("720p H.264 ~2 Mbps", 1200, 300, 2.0);

    /// <summary>480p H.264, ~1 Mbps: ~200 video pkt/s at ~900 B/packet.</summary>
    public static readonly MediaProfile Video480p = new("480p H.264 ~1 Mbps", 900, 200, 1.0);

    /// <summary>Opus audio rides alongside every video profile: ~50 pkt/s of ~120 B packets.</summary>
    public const int AudioPacketsPerSecond = 50;

    public static MediaProfile Resolve(string name) => name switch
    {
        "480p" => Video480p,
        "720p" => Video720p,
        _ => Video720p,
    };
}

/// <summary>
/// The single synthetic ingest RTP packet the SFU fans out: a fixed 12-byte RTP header (no CSRC or
/// extension) plus a random media payload sized to the profile. The sequence number and timestamp are
/// rewritten in place per pass so one buffer drives the whole run with zero per-packet allocation —
/// exactly the shape the receive path produces after SRTP-unprotecting a real broadcaster's stream.
/// </summary>
internal static class SyntheticIngest
{
    public const uint UpstreamSsrc = 0x1000_0000u;
    public const byte VideoPayloadType = 96;
    private const int HeaderLength = 12;

    public static byte[] Build(MediaProfile profile)
    {
        var payload = new byte[profile.VideoPacketBytes - HeaderLength];
        RandomNumberGenerator.Fill(payload);

        var header = new RtpHeader
        {
            Version = 2,
            PayloadType = VideoPayloadType,
            Ssrc = UpstreamSsrc,
            SequenceNumber = 0,
            Timestamp = 0,
            Marker = false,
        };

        var buffer = new byte[header.HeaderLength + payload.Length];
        var written = header.WriteTo(buffer);
        payload.CopyTo(buffer.AsSpan(written));
        return buffer;
    }

    /// <summary>Overwrites the sequence number (bytes 2-3) and timestamp (bytes 4-7), big-endian.</summary>
    public static void SetSequenceAndTimestamp(byte[] packet, ushort sequenceNumber, uint timestamp)
    {
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), sequenceNumber);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(4), timestamp);
    }
}
