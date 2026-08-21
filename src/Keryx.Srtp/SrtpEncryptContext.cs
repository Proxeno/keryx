using System.Runtime.InteropServices;
using Keryx.Core;

namespace Keryx.Srtp;

/// <summary>
/// Protects outbound RTP and RTCP for one direction of a media transport.
/// </summary>
/// <remarks>
/// <para>
/// One context covers an entire rtcp-mux / BUNDLE direction: per-SSRC cryptographic state
/// (rollover counter, highest sequence number, SRTCP index) is created the first time an SSRC is
/// seen and maintained independently thereafter.
/// </para>
/// <para>
/// Instances are stateful and not thread-safe; use one per direction and serialise access.
/// After construction the protect operations perform no per-packet allocation.
/// </para>
/// </remarks>
public sealed class SrtpEncryptContext : IDisposable
{
    private readonly ISrtpTransform _transform;
    private readonly IKeryxLogger _logger;
    private readonly Dictionary<uint, SrtpSendStreamState> _rtpStreams = [];
    private readonly Dictionary<uint, uint> _rtcpIndices = [];
    private bool _disposed;

    /// <summary>Creates an outbound context from master keying material.</summary>
    /// <param name="profile">The negotiated protection profile.</param>
    /// <param name="keys">The master key and salt for this direction.</param>
    /// <param name="logger">Optional logger; defaults to <see cref="NullLogger"/>.</param>
    /// <exception cref="ArgumentException">The key material does not match the profile.</exception>
    public SrtpEncryptContext(SrtpProtectionProfile profile, SrtpSessionKeys keys, IKeryxLogger? logger = null)
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
    /// Protects an RTP packet: encrypts the payload and appends the authentication tag.
    /// </summary>
    /// <param name="rtpPacket">A complete RTP packet (fixed header, CSRC list, optional extension, payload).</param>
    /// <param name="output">
    /// Receives the protected packet. Must be at least
    /// <c>rtpPacket.Length + Profile.RtpOverhead</c> bytes. May alias <paramref name="rtpPacket"/>
    /// provided both spans start at the same address, which allows protecting in place in a buffer
    /// that has tag room reserved at the end.
    /// </param>
    /// <returns>The number of bytes written to <paramref name="output"/>.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="rtpPacket"/> is not a well-formed RTP packet, or <paramref name="output"/> is too small.
    /// </exception>
    /// <exception cref="ObjectDisposedException">The context has been disposed.</exception>
    public int ProtectRtp(ReadOnlySpan<byte> rtpPacket, Span<byte> output)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!RtpHeaderView.TryParse(rtpPacket, out var headerLength, out var ssrc, out var sequenceNumber))
        {
            throw new ArgumentException("The buffer does not contain a well-formed RTP packet.", nameof(rtpPacket));
        }

        var required = rtpPacket.Length + _transform.RtpOverhead;
        if (output.Length < required)
        {
            throw new ArgumentException(
                $"The output buffer needs at least {required} bytes to hold the protected RTP packet.",
                nameof(output));
        }

        // The rollover counter is maintained by counting wraps, never by the RFC 3711 Appendix A
        // estimator: that is a receiver-side heuristic and using it here can rewind the packet index
        // into an already-used range. NextRolloverCounter also refuses an index that has already been
        // emitted, which turns what would be a silent keystream/nonce reuse into a loud failure.
        var stream = GetOrCreateStream(ssrc);
        var rolloverCounter = stream.NextRolloverCounter(sequenceNumber, ssrc);
        return _transform.ProtectRtp(rtpPacket, headerLength, ssrc, rolloverCounter, sequenceNumber, output);
    }

    /// <summary>
    /// Protects an RTCP packet: encrypts everything after the eight-octet header, appends the
    /// E-flag/SRTCP-index word with E set, and authenticates. The SRTCP index is maintained per
    /// SSRC and incremented modulo 2^31 after every packet (RFC 3711 Section 3.4).
    /// </summary>
    /// <param name="rtcpPacket">A complete RTCP (possibly compound) packet.</param>
    /// <param name="output">
    /// Receives the protected packet. Must be at least
    /// <c>rtcpPacket.Length + Profile.RtcpOverhead</c> bytes. May alias
    /// <paramref name="rtcpPacket"/> when both spans start at the same address.
    /// </param>
    /// <returns>The number of bytes written to <paramref name="output"/>.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="rtcpPacket"/> is not a well-formed RTCP packet, or <paramref name="output"/> is too small.
    /// </exception>
    /// <exception cref="ObjectDisposedException">The context has been disposed.</exception>
    public int ProtectRtcp(ReadOnlySpan<byte> rtcpPacket, Span<byte> output)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!RtpHeaderView.TryParseRtcp(rtcpPacket, out var ssrc))
        {
            throw new ArgumentException("The buffer does not contain a well-formed RTCP packet.", nameof(rtcpPacket));
        }

        var required = rtcpPacket.Length + _transform.RtcpOverhead;
        if (output.Length < required)
        {
            throw new ArgumentException(
                $"The output buffer needs at least {required} bytes to hold the protected RTCP packet.",
                nameof(output));
        }

        var current = NextSrtcpIndex(ssrc);
        return _transform.ProtectRtcp(rtcpPacket, ssrc, current, encrypt: true, output);
    }

    /// <summary>
    /// Overrides the next SRTCP index for <paramref name="ssrc"/>. Exposed for reproducing
    /// published test vectors, which fix the index.
    /// </summary>
    internal void SetNextSrtcpIndex(uint ssrc, uint index) => _rtcpIndices[ssrc] = index & SrtcpIndexWord.IndexMask;

    /// <summary>
    /// Protects RTCP with the E flag clear, i.e. authenticated but not encrypted. The public API
    /// always encrypts (RFC 3711 Section 9.1 makes that the safe default for WebRTC); this exists
    /// so the corresponding receive path can be exercised.
    /// </summary>
    internal int ProtectRtcpWithoutEncryption(ReadOnlySpan<byte> rtcpPacket, Span<byte> output)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!RtpHeaderView.TryParseRtcp(rtcpPacket, out var ssrc))
        {
            throw new ArgumentException("The buffer does not contain a well-formed RTCP packet.", nameof(rtcpPacket));
        }

        var current = NextSrtcpIndex(ssrc);
        return _transform.ProtectRtcp(rtcpPacket, ssrc, current, encrypt: false, output);
    }

    /// <summary>
    /// Returns the SRTCP index to protect the next packet for <paramref name="ssrc"/> with, and
    /// advances the counter.
    /// </summary>
    /// <remarks>
    /// RFC 3711 Section 9.2 caps one master key at 2^31 SRTCP packets, which is exactly the size of
    /// the 31-bit index field. Wrapping past it would restart the index at 0 and repeat every AES-CM
    /// IV and RFC 7714 Section 9.1 GCM nonce the session has already used, so the sender stops
    /// instead. Reaching this requires 2^31 RTCP packets under one DTLS handshake — decades at any
    /// realistic RTCP interval — but the limit is a MUST, and silently wrapping is the one outcome
    /// that must not happen.
    /// </remarks>
    private uint NextSrtcpIndex(uint ssrc)
    {
        ref var index = ref CollectionsMarshal.GetValueRefOrAddDefault(_rtcpIndices, ssrc, out _);
        var current = index;
        if (current > SrtcpIndexWord.IndexMask)
        {
            throw new InvalidOperationException(
                $"The SRTCP index for SSRC 0x{ssrc:x8} has reached the RFC 3711 Section 9.2 limit of 2^31 packets "
                + "for one master key. The session must be rekeyed; continuing would repeat an SRTCP nonce.");
        }

        index = current + 1;
        return current;
    }

    private SrtpSendStreamState GetOrCreateStream(uint ssrc)
    {
        ref var stream = ref CollectionsMarshal.GetValueRefOrAddDefault(_rtpStreams, ssrc, out var existed);
        if (!existed)
        {
            stream = new SrtpSendStreamState();
            if (_logger.IsEnabled(KeryxLogLevel.Debug))
            {
                _logger.Log(KeryxLogLevel.Debug, $"SRTP: new outbound stream for SSRC 0x{ssrc:x8}.");
            }
        }

        return stream!;
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
