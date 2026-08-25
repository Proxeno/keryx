using System.Collections;

namespace Keryx;

/// <summary>
/// One entry in a <see cref="RtcStatsReport"/>, shaped after the W3C WebRTC statistics dictionaries
/// (<see href="https://www.w3.org/TR/webrtc-stats/">webrtc-stats</see>). Every stat object carries the
/// three members the spec's <c>RTCStats</c> base defines: a report-unique <see cref="Id"/>, a
/// <see cref="Type"/> discriminator, and the <see cref="Timestamp"/> the sample was taken.
/// </summary>
/// <remarks>
/// This is an additive, standards-shaped view over the same counters
/// <see cref="PeerConnection.GetStats"/> already exposes as <see cref="PeerConnectionStats"/>; the
/// Keryx-specific snapshot is unchanged. Fields Keryx does not yet measure are left
/// <see langword="null"/> (documented per member) rather than fabricated.
/// </remarks>
public abstract record RtcStat
{
    /// <summary>Initialises the shared <c>RTCStats</c> members.</summary>
    /// <param name="id">The report-unique identifier.</param>
    /// <param name="type">The W3C stats type discriminator, for example <c>inbound-rtp</c>.</param>
    /// <param name="timestamp">The instant the sample was taken.</param>
    protected RtcStat(string id, string type, DateTimeOffset timestamp)
    {
        Id = id;
        Type = type;
        Timestamp = timestamp;
    }

    /// <summary>The identifier, unique within the report, other stats reference by id.</summary>
    public string Id { get; }

    /// <summary>The W3C <c>RTCStatsType</c> discriminator, for example <c>outbound-rtp</c> or <c>codec</c>.</summary>
    public string Type { get; }

    /// <summary>The instant this sample was taken, from the connection's configured time source.</summary>
    public DateTimeOffset Timestamp { get; }
}

/// <summary>
/// A negotiated codec (W3C <c>RTCCodecStats</c>, type <c>codec</c>): the payload type, its MIME type,
/// clock rate, channel count and fmtp line.
/// </summary>
public sealed record RtcCodecStats : RtcStat
{
    /// <summary>Creates a codec stat.</summary>
    /// <param name="id">The report-unique identifier.</param>
    /// <param name="timestamp">The instant the sample was taken.</param>
    public RtcCodecStats(string id, DateTimeOffset timestamp)
        : base(id, "codec", timestamp)
    {
    }

    /// <summary>The RTP payload type the codec is bound to in this session.</summary>
    public required uint PayloadType { get; init; }

    /// <summary>The MIME type, for example <c>video/H264</c> or <c>audio/opus</c>.</summary>
    public required string MimeType { get; init; }

    /// <summary>The codec clock rate in Hz.</summary>
    public required uint ClockRate { get; init; }

    /// <summary>The channel count (audio), or <see langword="null"/> when not applicable.</summary>
    public uint? Channels { get; init; }

    /// <summary>The <c>a=fmtp</c> parameter line as negotiated, or <see langword="null"/> when none.</summary>
    public string? SdpFmtpLine { get; init; }
}

/// <summary>
/// Statistics for one received RTP stream (W3C <c>RTCInboundRtpStreamStats</c>, type
/// <c>inbound-rtp</c>).
/// </summary>
public sealed record RtcInboundRtpStreamStats : RtcStat
{
    /// <summary>Creates an inbound-rtp stat.</summary>
    /// <param name="id">The report-unique identifier.</param>
    /// <param name="timestamp">The instant the sample was taken.</param>
    public RtcInboundRtpStreamStats(string id, DateTimeOffset timestamp)
        : base(id, "inbound-rtp", timestamp)
    {
    }

    /// <summary>The synchronisation source of the received stream.</summary>
    public required uint Ssrc { get; init; }

    /// <summary>The media kind, <c>audio</c> or <c>video</c>.</summary>
    public required string Kind { get; init; }

    /// <summary>RTP packets received from this source, from the RFC 3550 reception statistics.</summary>
    public required long PacketsReceived { get; init; }

    /// <summary>Cumulative packets lost (signed; duplicates can drive it negative), RFC 3550 §6.4.1.</summary>
    public required long PacketsLost { get; init; }

    /// <summary>Interarrival jitter in seconds, RFC 3550 A.8, or <see langword="null"/> without a clock rate.</summary>
    public double? Jitter { get; init; }

    /// <summary>The id of the <see cref="RtcCodecStats"/> this stream decodes with, or <see langword="null"/>.</summary>
    public string? CodecId { get; init; }

    /// <summary>The payload type in use, or <see langword="null"/> when the codec is not yet resolved.</summary>
    public uint? PayloadType { get; init; }

    /// <summary>
    /// NACK packets this receiver generated for the stream (automatic receiver NACK, video only), or
    /// <see langword="null"/>. Zero when <see cref="PeerConnectionConfig.EnableReceiverNack"/> is unset.
    /// </summary>
    public long? NackCount { get; init; }

    // Not-yet-available W3C fields for inbound-rtp: bytesReceived (payload bytes are not counted
    // per-source; only the connection-wide RtpPacketsReceived exists), framesDecoded / framesReceived
    // (Keryx does not own a decoder), and firCount / pliCount SENT by this receiver (only feedback
    // received is counted). They are intentionally omitted rather than reported as fabricated values.
}

/// <summary>
/// Statistics for one sent RTP stream (W3C <c>RTCOutboundRtpStreamStats</c>, type <c>outbound-rtp</c>).
/// </summary>
public sealed record RtcOutboundRtpStreamStats : RtcStat
{
    /// <summary>Creates an outbound-rtp stat.</summary>
    /// <param name="id">The report-unique identifier.</param>
    /// <param name="timestamp">The instant the sample was taken.</param>
    public RtcOutboundRtpStreamStats(string id, DateTimeOffset timestamp)
        : base(id, "outbound-rtp", timestamp)
    {
    }

    /// <summary>The synchronisation source of the sent stream.</summary>
    public required uint Ssrc { get; init; }

    /// <summary>The media kind, <c>audio</c> or <c>video</c>.</summary>
    public required string Kind { get; init; }

    /// <summary>RTP packets sent, retransmissions excluded.</summary>
    public required long PacketsSent { get; init; }

    /// <summary>RTP payload octets sent, excluding headers and SRTP overhead.</summary>
    public required long BytesSent { get; init; }

    /// <summary>The id of the <see cref="RtcCodecStats"/> this stream encodes with, or <see langword="null"/>.</summary>
    public string? CodecId { get; init; }

    /// <summary>The payload type in use, or <see langword="null"/> before negotiation settles.</summary>
    public uint? PayloadType { get; init; }

    /// <summary>RFC 4588 RTX packets sent, or <see langword="null"/> when retransmission is not negotiated.</summary>
    public long? RetransmittedPacketsSent { get; init; }

    /// <summary>RFC 4588 RTX bytes sent, or <see langword="null"/> when retransmission is not negotiated.</summary>
    public long? RetransmittedBytesSent { get; init; }

    /// <summary>Generic NACK packets received for this stream, or <see langword="null"/> when not tracked.</summary>
    public long? NackCount { get; init; }

    /// <summary>Full Intra Requests received for this stream (video), or <see langword="null"/>.</summary>
    public long? FirCount { get; init; }

    /// <summary>Picture Loss Indications received for this stream (video), or <see langword="null"/>.</summary>
    public long? PliCount { get; init; }

    /// <summary>
    /// The congestion controller's current target bitrate in bits per second (video), or
    /// <see langword="null"/> when no controller is active.
    /// </summary>
    public double? TargetBitrate { get; init; }
}

/// <summary>
/// What the remote peer reported about a stream this endpoint sends (W3C
/// <c>RTCRemoteInboundRtpStreamStats</c>, type <c>remote-inbound-rtp</c>), from an RTCP reception
/// report block.
/// </summary>
public sealed record RtcRemoteInboundRtpStreamStats : RtcStat
{
    /// <summary>Creates a remote-inbound-rtp stat.</summary>
    /// <param name="id">The report-unique identifier.</param>
    /// <param name="timestamp">The instant the report arrived.</param>
    public RtcRemoteInboundRtpStreamStats(string id, DateTimeOffset timestamp)
        : base(id, "remote-inbound-rtp", timestamp)
    {
    }

    /// <summary>The synchronisation source the report block described (the local send SSRC).</summary>
    public required uint Ssrc { get; init; }

    /// <summary>The media kind, <c>audio</c> or <c>video</c>.</summary>
    public required string Kind { get; init; }

    /// <summary>Cumulative packets the peer reports lost on this stream (signed), RFC 3550 §6.4.1.</summary>
    public required long PacketsLost { get; init; }

    /// <summary>Fraction of packets lost since the previous report, 0 to 1.</summary>
    public required double FractionLost { get; init; }

    /// <summary>Interarrival jitter in seconds, or <see langword="null"/> when the clock rate is unknown.</summary>
    public double? Jitter { get; init; }

    /// <summary>Round-trip time in seconds from the report's LSR/DLSR, or <see langword="null"/>.</summary>
    public double? RoundTripTime { get; init; }

    /// <summary>The id of the local <see cref="RtcOutboundRtpStreamStats"/> this report refers to.</summary>
    public string? LocalId { get; init; }
}

/// <summary>
/// Transport-level statistics (W3C <c>RTCTransportStats</c>, type <c>transport</c>): the DTLS state, the
/// selected candidate pair, and the negotiated ciphers.
/// </summary>
public sealed record RtcTransportStats : RtcStat
{
    /// <summary>Creates a transport stat.</summary>
    /// <param name="id">The report-unique identifier.</param>
    /// <param name="timestamp">The instant the sample was taken.</param>
    public RtcTransportStats(string id, DateTimeOffset timestamp)
        : base(id, "transport", timestamp)
    {
    }

    /// <summary>The DTLS transport state, lower-cased W3C spelling (for example <c>connected</c>).</summary>
    public required string DtlsState { get; init; }

    /// <summary>The id of the selected <see cref="RtcCandidatePairStats"/>, or <see langword="null"/>.</summary>
    public string? SelectedCandidatePairId { get; init; }

    /// <summary>The negotiated DTLS cipher suite name, or <see langword="null"/> before the handshake.</summary>
    public string? DtlsCipher { get; init; }

    /// <summary>The negotiated SRTP protection profile name, or <see langword="null"/> before keying.</summary>
    public string? SrtpCipher { get; init; }

    // Not-yet-available W3C fields for transport: bytesSent / bytesReceived / packetsSent /
    // packetsReceived are not aggregated at the transport layer (per-stream RTP counters exist, but a
    // transport-wide byte tally including STUN/DTLS/SCTP is not maintained), so they are omitted.
}

/// <summary>
/// The selected ICE candidate pair (W3C <c>RTCIceCandidatePairStats</c>, type <c>candidate-pair</c>).
/// </summary>
public sealed record RtcCandidatePairStats : RtcStat
{
    /// <summary>Creates a candidate-pair stat.</summary>
    /// <param name="id">The report-unique identifier.</param>
    /// <param name="timestamp">The instant the sample was taken.</param>
    public RtcCandidatePairStats(string id, DateTimeOffset timestamp)
        : base(id, "candidate-pair", timestamp)
    {
    }

    /// <summary>The id of the local <see cref="RtcIceCandidateStats"/> of the pair.</summary>
    public required string LocalCandidateId { get; init; }

    /// <summary>The id of the remote <see cref="RtcIceCandidateStats"/> of the pair.</summary>
    public required string RemoteCandidateId { get; init; }

    /// <summary>The pair's check state, lower-cased W3C spelling (for example <c>succeeded</c>).</summary>
    public required string State { get; init; }

    /// <summary>True once the controlling agent nominated the pair with USE-CANDIDATE.</summary>
    public required bool Nominated { get; init; }

    // Not-yet-available W3C fields for candidate-pair: currentRoundTripTime (the ICE agent does not
    // yet time its STUN connectivity/consent exchanges) and bytesSent / bytesReceived / packetsSent /
    // packetsReceived (no per-pair transport byte counters) are omitted.
}

/// <summary>
/// One ICE candidate of the selected pair (W3C <c>RTCIceCandidateStats</c>, type
/// <c>local-candidate</c> or <c>remote-candidate</c>).
/// </summary>
public sealed record RtcIceCandidateStats : RtcStat
{
    /// <summary>Creates a candidate stat.</summary>
    /// <param name="id">The report-unique identifier.</param>
    /// <param name="type">Either <c>local-candidate</c> or <c>remote-candidate</c>.</param>
    /// <param name="timestamp">The instant the sample was taken.</param>
    public RtcIceCandidateStats(string id, string type, DateTimeOffset timestamp)
        : base(id, type, timestamp)
    {
    }

    /// <summary>The candidate's IP address, as text.</summary>
    public required string Address { get; init; }

    /// <summary>The candidate's port.</summary>
    public required int Port { get; init; }

    /// <summary>The transport protocol, for example <c>udp</c>.</summary>
    public required string Protocol { get; init; }

    /// <summary>The candidate type: <c>host</c>, <c>srflx</c>, <c>prflx</c> or <c>relay</c>.</summary>
    public required string CandidateType { get; init; }
}

/// <summary>
/// A W3C-shaped statistics report (<see href="https://www.w3.org/TR/webrtc-stats/">webrtc-stats</see>
/// <c>RTCStatsReport</c>): an id-keyed, immutable collection of <see cref="RtcStat"/> objects, returned
/// by <see cref="PeerConnection.GetStatsReport"/>.
/// </summary>
public sealed class RtcStatsReport : IReadOnlyCollection<RtcStat>
{
    private readonly IReadOnlyList<RtcStat> _stats;
    private readonly Dictionary<string, RtcStat> _byId;

    /// <summary>Builds a report from a materialised set of stat objects.</summary>
    /// <param name="stats">The stat objects, each with a report-unique <see cref="RtcStat.Id"/>.</param>
    public RtcStatsReport(IReadOnlyList<RtcStat> stats)
    {
        ArgumentNullException.ThrowIfNull(stats);
        _stats = stats;
        _byId = new Dictionary<string, RtcStat>(stats.Count, StringComparer.Ordinal);
        foreach (var stat in stats)
        {
            _byId[stat.Id] = stat;
        }
    }

    /// <summary>The number of stat objects in the report.</summary>
    public int Count => _stats.Count;

    /// <summary>Looks up a stat by its <see cref="RtcStat.Id"/>.</summary>
    /// <param name="id">The identifier to resolve.</param>
    /// <returns>The stat with that id.</returns>
    public RtcStat this[string id] => _byId[id];

    /// <summary>Tries to look up a stat by its <see cref="RtcStat.Id"/>.</summary>
    /// <param name="id">The identifier to resolve.</param>
    /// <param name="stat">The stat, when found.</param>
    /// <returns>True when a stat with that id exists.</returns>
    public bool TryGet(string id, out RtcStat? stat) => _byId.TryGetValue(id, out stat);

    /// <summary>Enumerates the stat objects of one derived type.</summary>
    /// <typeparam name="T">The <see cref="RtcStat"/> subtype to filter to.</typeparam>
    /// <returns>Every stat assignable to <typeparamref name="T"/>, in report order.</returns>
    public IEnumerable<T> OfType<T>()
        where T : RtcStat
        => _stats.OfType<T>();

    /// <inheritdoc />
    public IEnumerator<RtcStat> GetEnumerator() => _stats.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
