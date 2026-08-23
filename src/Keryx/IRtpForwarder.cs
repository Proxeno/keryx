namespace Keryx;

/// <summary>
/// A handle onto one media kind's outbound send track, for forwarding already-packetized RTP payloads
/// verbatim onto the SSRC and sequence space this <see cref="PeerConnection"/> owns for that kind.
/// </summary>
/// <remarks>
/// <para>
/// This is the subscriber-egress primitive an SFU gateway holds in a hot fan-out loop: the upstream
/// (broadcaster) media is already codec-packetized, so the forwarder never re-packetizes. It rewrites
/// each packet onto this subscriber's owned SSRC with a monotonic sequence number, uses the supplied
/// timestamp as the RTP timestamp, and stamps the marker bit and payload type the caller passes —
/// then protects it with SRTP and paces it exactly as <see cref="PeerConnection.SendVideoFrame"/> and
/// <see cref="PeerConnection.SendAudioFrame"/> do. Each emitted packet is recorded in this
/// subscriber's send history, so an inbound NACK is served as an RFC 4588 RTX repair automatically
/// when retransmission was negotiated.
/// </para>
/// <para>
/// The handle is stable for the connection's lifetime; obtain it once with
/// <see cref="PeerConnection.GetForwarder"/> and reuse it. <see cref="TryForwardRtp"/> never throws
/// and returns <see langword="false"/> when the track is not ready, so one dead subscriber cannot
/// break a fan-out loop.
/// </para>
/// </remarks>
public interface IRtpForwarder
{
    /// <summary>The media kind this forwarder emits.</summary>
    MediaKind Kind { get; }

    /// <summary>
    /// The local synchronisation source every forwarded packet carries — the send SSRC
    /// <see cref="PeerConnection"/> owns for <see cref="Kind"/>.
    /// </summary>
    uint Ssrc { get; }

    /// <summary>
    /// Forwards one already-packetized RTP payload onto this subscriber's send track. See
    /// <see cref="PeerConnection.TryForwardRtp"/> for the exact semantics.
    /// </summary>
    /// <param name="payload">The RTP payload, written verbatim; never re-packetized.</param>
    /// <param name="rtpTimestamp">The RTP timestamp to stamp on the packet.</param>
    /// <param name="marker">The marker bit.</param>
    /// <param name="payloadType">The payload type this subscriber negotiated.</param>
    /// <returns>True when the packet reached the send path; false when the track is not ready.</returns>
    bool TryForwardRtp(ReadOnlySpan<byte> payload, uint rtpTimestamp, bool marker, byte payloadType);
}
