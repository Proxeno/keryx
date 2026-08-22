using Keryx.Rtp;

namespace Keryx.Rtp.Tests.Simulcast;

/// <summary>Builds RTP packet buffers carrying RFC 8852 RID / repaired-RID header extensions.</summary>
internal static class SimulcastTestPackets
{
    public const byte MidId = 1;
    public const byte RidId = 2;
    public const byte RepairedRidId = 3;

    public static byte[] WithRid(string rid, uint ssrc, ushort seq, uint ts, byte payloadType = 96, byte[]? payload = null) =>
        Build(ssrc, seq, ts, payloadType, payload, (RidId, rid));

    public static byte[] WithRepairedRid(string rid, uint ssrc, ushort seq, uint ts, byte payloadType = 97, byte[]? payload = null) =>
        Build(ssrc, seq, ts, payloadType, payload, (RepairedRidId, rid));

    public static byte[] Plain(uint ssrc, ushort seq, uint ts, byte payloadType = 96, byte[]? payload = null) =>
        Build(ssrc, seq, ts, payloadType, payload);

    private static byte[] Build(
        uint ssrc,
        ushort seq,
        uint ts,
        byte payloadType,
        byte[]? payload,
        params (byte Id, string Value)[] extensions)
    {
        payload ??= [0x01, 0x02, 0x03, 0x04];
        Span<byte> body = stackalloc byte[64];
        var writer = new RtpOneByteExtensionWriter(body);
        var hasExtension = extensions.Length > 0;
        foreach (var (id, value) in extensions)
        {
            writer.TryAppend(id, System.Text.Encoding.ASCII.GetBytes(value));
        }

        var extensionLength = hasExtension ? writer.Finish() : 0;

        var header = new RtpHeader
        {
            Version = 2,
            PayloadType = payloadType,
            SequenceNumber = seq,
            Timestamp = ts,
            Ssrc = ssrc,
            HasExtension = hasExtension,
            ExtensionProfile = hasExtension ? RtpHeaderExtension.OneByteProfile : (ushort)0,
            ExtensionData = hasExtension ? body[..extensionLength] : default,
        };

        var buffer = new byte[header.HeaderLength + payload.Length];
        var written = header.WriteTo(buffer);
        payload.CopyTo(buffer.AsSpan(written));
        return buffer;
    }
}
