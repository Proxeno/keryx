using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Keryx.Core;

namespace Keryx.Srtp;

/// <summary>
/// Unprotects inbound SRTP and SRTCP for one direction of a media transport.
/// </summary>
/// <remarks>
/// <para>
/// One context covers an entire rtcp-mux / BUNDLE direction: an independent rollover counter and
/// replay list are created the first time an SSRC is seen. Nothing here throws on wire data —
/// malformed, forged and replayed packets all return <see langword="false"/> and are logged at
/// <see cref="KeryxLogLevel.Debug"/>.
/// </para>
/// <para>
/// Instances are stateful and not thread-safe; use one per direction and serialise access.
/// After construction the unprotect operations perform no per-packet allocation.
/// </para>
/// </remarks>
public sealed class SrtpDecryptContext : IDisposable
{
    private readonly ISrtpTransform _transform;
    private readonly IKeryxLogger _logger;
    private readonly Dictionary<uint, SrtpStreamState> _rtpStreams = [];
    private readonly Dictionary<uint, SrtpReplayWindow> _rtcpReplay = [];
    private bool _disposed;

    /// <summary>Creates an inbound context from master keying material.</summary>
    /// <param name="profile">The negotiated protection profile.</param>
    /// <param name="keys">The master key and salt for this direction.</param>
    /// <param name="logger">Optional logger; defaults to <see cref="NullLogger"/>.</param>
    /// <exception cref="ArgumentException">The key material does not match the profile.</exception>
    public SrtpDecryptContext(SrtpProtectionProfile profile, SrtpSessionKeys keys, IKeryxLogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(keys);
        Profile = profile;
        _logger = logger ?? NullLogger.Instance;
        _transform = SrtpTransformFactory.Create(profile, keys);
    }

    /// <summary>The protection profile in force.</summary>
    public SrtpProtectionProfile Profile { get; }

    /// <summary>
    /// Verifies and decrypts an SRTP packet.
    /// </summary>
    /// <param name="srtpPacket">The packet as received from the network.</param>
    /// <param name="output">
    /// Receives the plaintext RTP packet. Must be at least <c>srtpPacket.Length</c> bytes (the
    /// surplus over the plaintext is used as authentication scratch space). May alias
    /// <paramref name="srtpPacket"/> when both spans start at the same address, which allows
    /// unprotecting in place.
    /// </param>
    /// <param name="length">On success, the length of the recovered RTP packet.</param>
    /// <returns>
    /// <see langword="true"/> when the packet authenticated and was not a replay; otherwise
    /// <see langword="false"/>, in which case the contents of <paramref name="output"/> are undefined.
    /// </returns>
    /// <exception cref="ArgumentException"><paramref name="output"/> is too small.</exception>
    /// <exception cref="ObjectDisposedException">The context has been disposed.</exception>
    public bool TryUnprotectRtp(ReadOnlySpan<byte> srtpPacket, Span<byte> output, out int length)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        length = 0;

        if (output.Length < srtpPacket.Length)
        {
            throw new ArgumentException(
                $"The output buffer needs at least {srtpPacket.Length} bytes to unprotect this packet.",
                nameof(output));
        }

        if (!RtpHeaderView.TryParse(srtpPacket, out var headerLength, out var ssrc, out var sequenceNumber))
        {
            Debug("SRTP: dropping packet that is not well-formed RTP.");
            return false;
        }

        if (srtpPacket.Length < headerLength + _transform.RtpOverhead)
        {
            Debug($"SRTP: dropping {srtpPacket.Length}-byte packet, too short for a {_transform.RtpOverhead}-byte tag.");
            return false;
        }

        // State for an unseen SSRC is not created until the packet authenticates. The SSRC is read
        // straight off the wire, so allocating on first sight let anyone who can reach this socket
        // pin a SrtpStreamState plus a dictionary entry per forged SSRC — 2^32 of them, never
        // evicted, for the price of a 22-byte datagram each.
        var known = _rtpStreams.TryGetValue(ssrc, out var stream);

        // RFC 3711 Section 3.3 processing order: estimate the index, consult the replay list,
        // verify the tag, decrypt, and only then commit ROC / s_l / replay state.
        var candidate = known ? stream!.EstimateRolloverCounter(sequenceNumber) : 0;
        var index = SrtpPacketIndex.Compose(candidate, sequenceNumber);

        if (known && !stream!.Replay.IsAcceptable(index))
        {
            Debug($"SRTP: dropping replayed packet, SSRC 0x{ssrc:x8} index {index}.");
            return false;
        }

        if (!_transform.TryUnprotectRtp(srtpPacket, headerLength, ssrc, candidate, sequenceNumber, output, out length))
        {
            length = 0;
            Debug($"SRTP: authentication failed for SSRC 0x{ssrc:x8} seq {sequenceNumber}.");
            return false;
        }

        if (!known)
        {
            stream = new SrtpStreamState(ssrc);
            _rtpStreams[ssrc] = stream;
            if (_logger.IsEnabled(KeryxLogLevel.Debug))
            {
                _logger.Log(KeryxLogLevel.Debug, $"SRTP: new inbound stream for SSRC 0x{ssrc:x8}.");
            }
        }

        stream!.Commit(candidate, sequenceNumber);
        stream.Replay.Commit(index);
        return true;
    }

    /// <summary>
    /// Verifies and decrypts an SRTCP packet.
    /// </summary>
    /// <param name="srtcpPacket">The packet as received from the network.</param>
    /// <param name="output">
    /// Receives the plaintext RTCP packet. Must be at least <c>srtcpPacket.Length</c> bytes. May
    /// alias <paramref name="srtcpPacket"/> when both spans start at the same address.
    /// </param>
    /// <param name="length">On success, the length of the recovered RTCP packet.</param>
    /// <returns>
    /// <see langword="true"/> when the packet authenticated and was not a replay; otherwise
    /// <see langword="false"/>.
    /// </returns>
    /// <exception cref="ArgumentException"><paramref name="output"/> is too small.</exception>
    /// <exception cref="ObjectDisposedException">The context has been disposed.</exception>
    public bool TryUnprotectRtcp(ReadOnlySpan<byte> srtcpPacket, Span<byte> output, out int length)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        length = 0;

        if (output.Length < srtcpPacket.Length)
        {
            throw new ArgumentException(
                $"The output buffer needs at least {srtcpPacket.Length} bytes to unprotect this packet.",
                nameof(output));
        }

        if (srtcpPacket.Length < _transform.MinimumProtectedRtcpLength)
        {
            Debug($"SRTCP: dropping {srtcpPacket.Length}-byte packet, shorter than the minimum protected size.");
            return false;
        }

        if (!RtpHeaderView.TryParseRtcp(srtcpPacket, out var ssrc))
        {
            Debug("SRTCP: dropping packet that is not well-formed RTCP.");
            return false;
        }

        var wordOffset = _transform.SrtcpIndexWordOffset(srtcpPacket.Length);
        var word = BinaryPrimitives.ReadUInt32BigEndian(srtcpPacket.Slice(wordOffset, 4));
        var index = SrtcpIndexWord.Index(word);
        var encrypted = SrtcpIndexWord.IsEncrypted(word);

        // As on the SRTP path, the replay entry for an unseen SSRC is not created until the packet
        // authenticates. A default window accepts any first index, so the check below behaves
        // identically for a genuine first packet.
        _rtcpReplay.TryGetValue(ssrc, out var replay);
        if (!replay.IsAcceptable(index))
        {
            Debug($"SRTCP: dropping replayed packet, SSRC 0x{ssrc:x8} index {index}.");
            return false;
        }

        if (!_transform.TryUnprotectRtcp(srtcpPacket, ssrc, index, encrypted, output, out length))
        {
            length = 0;
            Debug($"SRTCP: authentication failed for SSRC 0x{ssrc:x8} index {index}.");
            return false;
        }

        replay.Commit(index);
        _rtcpReplay[ssrc] = replay;
        return true;
    }

    /// <summary>
    /// Number of SSRCs this context holds cryptographic state for. Entries are created only once a
    /// packet from that SSRC has authenticated, so forged traffic cannot grow it.
    /// </summary>
    internal int TrackedStreamCount => _rtpStreams.Count + _rtcpReplay.Count;

    private void Debug(string message)
    {
        if (_logger.IsEnabled(KeryxLogLevel.Debug))
        {
            _logger.Log(KeryxLogLevel.Debug, message);
        }
    }

    /// <summary>Releases the derived session keys.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _transform.Dispose();
    }
}
