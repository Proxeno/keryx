namespace Keryx.Rtp.Packetization;

/// <summary>
/// Receives the RTP payloads a packetizer produces for one encoded frame.
/// </summary>
/// <remarks>
/// The interface hands the packetizer a destination buffer rather than a finished payload, so a
/// packetizer can build fragmentation and aggregation headers straight into the outgoing RTP packet
/// with no intermediate copy and no allocation. A typical implementation returns the region of a
/// pooled packet buffer that sits just past the RTP header, then hands the completed packet to SRTP
/// from <see cref="Commit"/>.
/// </remarks>
public interface IRtpPayloadWriter
{
    /// <summary>
    /// Returns a buffer for the next payload. The returned span must be at least
    /// <paramref name="sizeHint"/> bytes long; a longer span is allowed and the packetizer will simply
    /// use less of it.
    /// </summary>
    /// <param name="sizeHint">Minimum number of bytes the packetizer may write.</param>
    /// <returns>The destination for the next payload.</returns>
    Span<byte> GetPayloadBuffer(int sizeHint);

    /// <summary>
    /// Publishes the first <paramref name="length"/> bytes of the buffer most recently returned by
    /// <see cref="GetPayloadBuffer"/> as one RTP payload.
    /// </summary>
    /// <param name="length">Number of bytes written into that buffer.</param>
    /// <param name="marker">
    /// The RTP marker bit for this packet: set on the last packet of an access unit for video payload
    /// formats (RFC 3551 §4.1), clear for the audio formats Keryx packetizes.
    /// </param>
    void Commit(int length, bool marker);
}

/// <summary>
/// Splits an encoded media frame into RTP payloads according to a payload format specification.
/// </summary>
/// <remarks>
/// This is the extension seam for payload formats Keryx does not ship: an implementation needs
/// nothing from inside the assembly beyond this interface and <see cref="IRtpPayloadWriter"/>.
/// Implementations should be allocation-free on the packetizing path.
/// </remarks>
public interface IRtpPayloadizer
{
    /// <summary>The RTP clock rate of the payload format, in Hz.</summary>
    uint ClockRate { get; }

    /// <summary>
    /// The number of RTP timestamp ticks this frame occupies, when the payload format encodes its own
    /// duration; zero when it does not and the caller must supply capture timestamps instead.
    /// </summary>
    /// <param name="frame">The encoded frame.</param>
    /// <returns>The timestamp increment in <see cref="ClockRate"/> ticks, or zero if unknown.</returns>
    uint GetTimestampIncrement(ReadOnlySpan<byte> frame);

    /// <summary>
    /// Splits <paramref name="frame"/> into RTP payloads, publishing each through
    /// <paramref name="writer"/> in transmission order.
    /// </summary>
    /// <param name="frame">One encoded frame, in the format's natural container.</param>
    /// <param name="maxPayloadSize">
    /// Largest RTP payload the transport accepts, i.e. the path MTU less IP, UDP, RTP header and SRTP
    /// authentication-tag overhead.
    /// </param>
    /// <param name="writer">Receives the payloads.</param>
    /// <returns>The number of RTP packets produced.</returns>
    int Packetize(ReadOnlySpan<byte> frame, int maxPayloadSize, IRtpPayloadWriter writer);
}

/// <summary>One payload produced by a packetizer, together with the marker bit it should carry.</summary>
/// <param name="Data">The RTP payload bytes.</param>
/// <param name="Marker">The RTP marker bit for the packet carrying this payload.</param>
public readonly record struct RtpPayload(byte[] Data, bool Marker);

/// <summary>
/// An <see cref="IRtpPayloadWriter"/> that copies each payload into a fresh array and collects them.
/// Convenient for tests, tooling and non-hot-path callers; production senders should write straight
/// into their packet buffers instead.
/// </summary>
public sealed class CollectingRtpPayloadWriter : IRtpPayloadWriter
{
    private readonly List<RtpPayload> _payloads = [];
    private byte[] _scratch = [];

    /// <summary>The payloads collected so far, in transmission order.</summary>
    public IReadOnlyList<RtpPayload> Payloads => _payloads;

    /// <summary>Discards everything collected so far.</summary>
    public void Clear() => _payloads.Clear();

    /// <inheritdoc />
    public Span<byte> GetPayloadBuffer(int sizeHint)
    {
        if (_scratch.Length < sizeHint)
        {
            _scratch = new byte[sizeHint];
        }

        return _scratch;
    }

    /// <inheritdoc />
    public void Commit(int length, bool marker) =>
        _payloads.Add(new RtpPayload(_scratch.AsSpan(0, length).ToArray(), marker));
}
