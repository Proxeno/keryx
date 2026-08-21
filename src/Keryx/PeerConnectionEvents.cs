using Keryx.Rtp.Rtcp;

namespace Keryx;

/// <summary>
/// A locally gathered ICE candidate, ready to hand to signalling.
/// </summary>
/// <remarks>
/// Raised while <see cref="PeerConnection.CreateOfferAsync"/> or
/// <see cref="PeerConnection.CreateAnswerAsync"/> is gathering, so a trickling peer can start checks
/// before the full description is written. The same candidates also appear as <c>a=candidate</c> lines
/// in the returned SDP, which makes the description usable by a vanilla-ICE peer.
/// </remarks>
public sealed class LocalIceCandidateEventArgs : EventArgs
{
    /// <summary>Creates the arguments.</summary>
    /// <param name="candidate">The candidate in SDP attribute syntax, <c>candidate:…</c>.</param>
    /// <param name="sdpMid">The media identifier the candidate belongs to.</param>
    public LocalIceCandidateEventArgs(string candidate, string? sdpMid)
    {
        Candidate = candidate;
        SdpMid = sdpMid;
    }

    /// <summary>The candidate in SDP attribute syntax, including the <c>candidate:</c> prefix.</summary>
    public string Candidate { get; }

    /// <summary>
    /// The <c>a=mid</c> the candidate is scoped to. With BUNDLE this is the first mid, and a browser
    /// applies the candidate to the whole bundled transport.
    /// </summary>
    public string? SdpMid { get; }
}

/// <summary>A received Picture Loss Indication (RFC 4585 §6.3.1): the peer wants a fresh key frame.</summary>
public sealed class PliEventArgs : EventArgs
{
    /// <summary>Creates the arguments.</summary>
    /// <param name="senderSsrc">The SSRC of the endpoint that sent the feedback.</param>
    /// <param name="mediaSsrc">The SSRC of the stream a key frame is wanted for.</param>
    public PliEventArgs(uint senderSsrc, uint mediaSsrc)
    {
        SenderSsrc = senderSsrc;
        MediaSsrc = mediaSsrc;
    }

    /// <summary>The SSRC of the endpoint that sent the feedback.</summary>
    public uint SenderSsrc { get; }

    /// <summary>The SSRC of the media stream a key frame is wanted for.</summary>
    public uint MediaSsrc { get; }
}

/// <summary>A received Full Intra Request (RFC 5104 §4.3.1).</summary>
/// <remarks>
/// FIR carries a per-target sequence number so a repeated request can be told apart from a duplicate
/// of the previous one; only act on it when <see cref="SequenceNumber"/> has advanced.
/// </remarks>
public sealed class FirEventArgs : EventArgs
{
    /// <summary>Creates the arguments.</summary>
    /// <param name="senderSsrc">The SSRC of the endpoint that sent the feedback.</param>
    /// <param name="mediaSsrc">The media SSRC field of the feedback header.</param>
    /// <param name="targetSsrc">The SSRC named by the FIR entry — the stream to re-key.</param>
    /// <param name="sequenceNumber">The FIR command sequence number.</param>
    public FirEventArgs(uint senderSsrc, uint mediaSsrc, uint targetSsrc, byte sequenceNumber)
    {
        SenderSsrc = senderSsrc;
        MediaSsrc = mediaSsrc;
        TargetSsrc = targetSsrc;
        SequenceNumber = sequenceNumber;
    }

    /// <summary>The SSRC of the endpoint that sent the feedback.</summary>
    public uint SenderSsrc { get; }

    /// <summary>The media SSRC field of the feedback header; zero in RFC 5104 FIR.</summary>
    public uint MediaSsrc { get; }

    /// <summary>The SSRC named by the FIR entry: the stream that must emit an intra frame.</summary>
    public uint TargetSsrc { get; }

    /// <summary>The FIR command sequence number, incremented by the requester per request.</summary>
    public byte SequenceNumber { get; }
}

/// <summary>A received Generic NACK (RFC 4585 §6.2.1) with its bitmask already expanded.</summary>
public sealed class NackEventArgs : EventArgs
{
    /// <summary>Creates the arguments.</summary>
    /// <param name="senderSsrc">The SSRC of the endpoint that sent the feedback.</param>
    /// <param name="mediaSsrc">The SSRC of the stream packets are missing from.</param>
    /// <param name="sequenceNumbers">Every missing RTP sequence number, in ascending wire order.</param>
    public NackEventArgs(uint senderSsrc, uint mediaSsrc, IReadOnlyList<ushort> sequenceNumbers)
    {
        SenderSsrc = senderSsrc;
        MediaSsrc = mediaSsrc;
        SequenceNumbers = sequenceNumbers;
    }

    /// <summary>The SSRC of the endpoint that sent the feedback.</summary>
    public uint SenderSsrc { get; }

    /// <summary>The SSRC of the media stream packets are missing from.</summary>
    public uint MediaSsrc { get; }

    /// <summary>
    /// Every sequence number the peer reports missing, with the run-length bitmasks already expanded.
    /// Keryx ships no RTX path, so this is a signal to act on (drop quality, force a key frame), not a
    /// retransmission request the stack will satisfy on its own.
    /// </summary>
    public IReadOnlyList<ushort> SequenceNumbers { get; }
}

/// <summary>A received transport-wide congestion control feedback packet, fully parsed.</summary>
public sealed class TransportCcEventArgs : EventArgs
{
    /// <summary>Creates the arguments.</summary>
    /// <param name="feedback">The parsed feedback packet.</param>
    public TransportCcEventArgs(RtcpTransportCcFeedback feedback) => Feedback = feedback;

    /// <summary>
    /// The parsed feedback: base sequence number, reference time and one
    /// <see cref="TransportCcPacketStatus"/> per reported packet with its arrival delta.
    /// </summary>
    public RtcpTransportCcFeedback Feedback { get; }
}

/// <summary>Reception statistics the peer reported about the streams this endpoint sends.</summary>
public sealed class ReceiverReportEventArgs : EventArgs
{
    private readonly DateTimeOffset _receivedAt;

    /// <summary>Creates the arguments.</summary>
    /// <param name="senderSsrc">The SSRC of the endpoint that sent the report.</param>
    /// <param name="reportBlocks">The reception report blocks the packet carried.</param>
    /// <param name="receivedAt">The wall-clock instant the report arrived, used for RTT.</param>
    public ReceiverReportEventArgs(
        uint senderSsrc,
        IReadOnlyList<RtcpReportBlock> reportBlocks,
        DateTimeOffset receivedAt)
    {
        SenderSsrc = senderSsrc;
        ReportBlocks = reportBlocks;
        _receivedAt = receivedAt;
    }

    /// <summary>The SSRC of the endpoint that sent the report.</summary>
    public uint SenderSsrc { get; }

    /// <summary>
    /// One block per stream the peer is receiving from this endpoint: fraction lost, cumulative loss,
    /// extended highest sequence number, interarrival jitter, LSR and DLSR.
    /// </summary>
    public IReadOnlyList<RtcpReportBlock> ReportBlocks { get; }

    /// <summary>The wall-clock instant this report was received.</summary>
    public DateTimeOffset ReceivedAt => _receivedAt;

    /// <summary>
    /// Computes the round-trip time from a report block using RFC 3550 §6.4.1 arithmetic:
    /// <c>RTT = now - DLSR - LSR</c>, all in compact NTP form.
    /// </summary>
    /// <param name="block">A block from <see cref="ReportBlocks"/>.</param>
    /// <returns>
    /// The round-trip time, or <see langword="null"/> when the peer has not yet received a sender
    /// report from this endpoint (<see cref="RtcpReportBlock.LastSenderReport"/> is zero).
    /// </returns>
    public TimeSpan? GetRoundTripTime(RtcpReportBlock block)
    {
        if (block.LastSenderReport == 0)
        {
            return null;
        }

        var now = NtpTime.ToCompact(NtpTime.FromDateTimeOffset(_receivedAt));
        var elapsed = unchecked(now - block.LastSenderReport);
        if (elapsed < block.DelaySinceLastSenderReport)
        {
            return TimeSpan.Zero;
        }

        return NtpTime.FromFixed16(elapsed - block.DelaySinceLastSenderReport);
    }
}

/// <summary>
/// The header fields of one received RTP packet, resolved against the negotiated session.
/// </summary>
/// <param name="Mid">The <c>a=mid</c> of the m-section the payload type belongs to, or null if unmatched.</param>
/// <param name="Kind">The media kind the payload type resolved to.</param>
/// <param name="PayloadType">The RTP payload type.</param>
/// <param name="Ssrc">The synchronisation source.</param>
/// <param name="SequenceNumber">The RTP sequence number.</param>
/// <param name="Timestamp">The RTP timestamp, in the codec's clock rate.</param>
/// <param name="Marker">The marker bit; for video it terminates an access unit.</param>
public readonly record struct RtpPacketInfo(
    string? Mid,
    MediaKind Kind,
    byte PayloadType,
    uint Ssrc,
    ushort SequenceNumber,
    uint Timestamp,
    bool Marker);

/// <summary>Receives one decrypted, validated inbound RTP packet.</summary>
/// <param name="info">The packet's header fields and the m-section it resolved to.</param>
/// <param name="payload">
/// The RTP payload, padding already stripped. Valid only for the duration of the call — copy it, or
/// feed it straight to a depacketizer, before returning.
/// </param>
public delegate void RtpPacketReceivedHandler(in RtpPacketInfo info, ReadOnlySpan<byte> payload);
