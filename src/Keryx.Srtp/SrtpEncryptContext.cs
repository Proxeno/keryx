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
    private readonly Dictionary<uint, SrtpStreamState> _rtpStreams = [];
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

        var stream = GetOrCreateStream(ssrc);
        var candidate = stream.EstimateRolloverCounter(sequenceNumber);
        var written = _transform.ProtectRtp(rtpPacket, headerLength, ssrc, candidate, sequenceNumber, output);
        stream.Commit(candidate, sequenceNumber);
        return written;
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

        ref var index = ref CollectionsMarshal.GetValueRefOrAddDefault(_rtcpIndices, ssrc, out _);
        var current = index;
        index = (current + 1) & SrtcpIndexWord.IndexMask;

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

        ref var index = ref CollectionsMarshal.GetValueRefOrAddDefault(_rtcpIndices, ssrc, out _);
        var current = index;
        index = (current + 1) & SrtcpIndexWord.IndexMask;

        return _transform.ProtectRtcp(rtcpPacket, ssrc, current, encrypt: false, output);
    }

    private SrtpStreamState GetOrCreateStream(uint ssrc)
    {
        ref var stream = ref CollectionsMarshal.GetValueRefOrAddDefault(_rtpStreams, ssrc, out var existed);
        if (!existed)
        {
            stream = new SrtpStreamState(ssrc);
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
