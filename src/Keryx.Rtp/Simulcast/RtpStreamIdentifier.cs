namespace Keryx.Rtp.Simulcast;

/// <summary>
/// The negotiated one-byte header-extension element identifiers that carry the RFC 8852 stream
/// identifiers. Each is the <c>a=extmap</c> id agreed for the corresponding URI, or <c>0</c> when the
/// extension was not negotiated.
/// </summary>
/// <param name="MidId">Element id for <c>urn:ietf:params:rtp-hdrext:sdes:mid</c>, or 0 if absent.</param>
/// <param name="RidId">Element id for <c>urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id</c>, or 0 if absent.</param>
/// <param name="RepairedRidId">
/// Element id for <c>urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id</c>, or 0 if absent.
/// </param>
public readonly record struct RtpStreamIdentifierExtensions(byte MidId, byte RidId, byte RepairedRidId)
{
    /// <summary>True when the RID extension was negotiated and RID-based demux is possible.</summary>
    public bool HasRid => RidId is >= 1 and <= 14;

    /// <summary>True when the repaired-RID extension was negotiated.</summary>
    public bool HasRepairedRid => RepairedRidId is >= 1 and <= 14;

    /// <summary>True when the MID extension was negotiated.</summary>
    public bool HasMid => MidId is >= 1 and <= 14;
}

/// <summary>
/// Reads the RFC 8852 stream identifiers — MID, RID and repaired RID — from an RTP header's one-byte
/// extension elements. Every accessor is allocation-free and never throws; a missing or malformed
/// element simply yields <see langword="false"/>.
/// </summary>
public static class RtpStreamIdentifier
{
    /// <summary>Reads the RID (<c>rtp-stream-id</c>) element as a layer identifier.</summary>
    /// <param name="header">The parsed RTP header.</param>
    /// <param name="ridElementId">The negotiated element id for the RID extension.</param>
    /// <param name="layerId">On success, the RID as a <see cref="SimulcastLayerId"/>.</param>
    /// <returns>True when a well-formed RID element is present.</returns>
    public static bool TryGetRid(in RtpHeader header, byte ridElementId, out SimulcastLayerId layerId)
    {
        layerId = default;
        return ridElementId is >= 1 and <= 14
            && header.TryGetExtension(ridElementId, out var data)
            && SimulcastLayerId.TryCreate(data, out layerId);
    }

    /// <summary>Reads the repaired-RID element as a layer identifier (present on RTX packets).</summary>
    /// <param name="header">The parsed RTP header.</param>
    /// <param name="repairedRidElementId">The negotiated element id for the repaired-RID extension.</param>
    /// <param name="layerId">On success, the repaired RID as a <see cref="SimulcastLayerId"/>.</param>
    /// <returns>True when a well-formed repaired-RID element is present.</returns>
    public static bool TryGetRepairedRid(in RtpHeader header, byte repairedRidElementId, out SimulcastLayerId layerId)
    {
        layerId = default;
        return repairedRidElementId is >= 1 and <= 14
            && header.TryGetExtension(repairedRidElementId, out var data)
            && SimulcastLayerId.TryCreate(data, out layerId);
    }

    /// <summary>Reads the MID (<c>sdes:mid</c>) element as raw bytes.</summary>
    /// <param name="header">The parsed RTP header.</param>
    /// <param name="midElementId">The negotiated element id for the MID extension.</param>
    /// <param name="mid">On success, the MID body; aliases the header buffer.</param>
    /// <returns>True when a MID element is present.</returns>
    public static bool TryGetMid(in RtpHeader header, byte midElementId, out ReadOnlySpan<byte> mid)
    {
        if (midElementId is >= 1 and <= 14 && header.TryGetExtension(midElementId, out var data) && !data.IsEmpty)
        {
            mid = data;
            return true;
        }

        mid = default;
        return false;
    }
}
