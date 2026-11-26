using Keryx.Rtp.Packetization;

namespace Keryx;

/// <summary>How to turn one audio RTP payload into a duration, resolved once from the negotiated codec.</summary>
/// <remarks>
/// The sample rate the result is counted in is not always the RTP clock rate: G.722 samples audio at
/// 16 kHz while its RTP timestamp runs at 8 kHz (RFC 3551 §4.5.2). The private tag's zero value is
/// <see cref="Codec.Unknown"/>, so <c>default(AudioPayloadTiming)</c> means "cannot measure".
/// </remarks>
internal readonly struct AudioPayloadTiming
{
    private const uint OpusSampleRate = 48_000;

    private enum Codec : byte
    {
        Unknown = 0,
        Opus = 1,
        Pcm = 2,
        G722 = 3,
    }

    private readonly Codec _codec;
    private readonly uint _rtpClockRate;

    private AudioPayloadTiming(Codec codec, uint rtpClockRate)
    {
        _codec = codec;
        _rtpClockRate = rtpClockRate;
    }

    /// <summary>Resolves the timing rules for a negotiated encoding name, or "unknown" for anything else.</summary>
    /// <param name="encodingName">The negotiated <c>a=rtpmap</c> encoding name, compared case-insensitively.</param>
    /// <param name="rtpClockRate">The negotiated RTP clock rate, used by PCMU/PCMA (and G.722's clock).</param>
    /// <returns>The resolved timing; <c>default</c> when the codec cannot be measured.</returns>
    internal static AudioPayloadTiming FromCodec(string? encodingName, uint rtpClockRate)
    {
        if (string.Equals(encodingName, "opus", StringComparison.OrdinalIgnoreCase))
        {
            // RFC 7587 §4.1: Opus always runs a 48 kHz RTP clock, whatever the encoder's rate.
            return new AudioPayloadTiming(Codec.Opus, rtpClockRate);
        }

        if (string.Equals(encodingName, "PCMU", StringComparison.OrdinalIgnoreCase)
            || string.Equals(encodingName, "PCMA", StringComparison.OrdinalIgnoreCase))
        {
            // RFC 3551 §4.5.14: G.711 is 8 kHz mono, one audio sample per payload octet.
            return new AudioPayloadTiming(Codec.Pcm, rtpClockRate);
        }

        if (string.Equals(encodingName, "G722", StringComparison.OrdinalIgnoreCase))
        {
            // RFC 3551 §4.5.2: G.722 audio is sampled at 16 kHz, but its RTP timestamp clock is 8 kHz,
            // so one payload octet covers two audio samples and one RTP tick.
            return new AudioPayloadTiming(Codec.G722, rtpClockRate);
        }

        return default;
    }

    /// <summary>
    /// The packetizer for the negotiated codec. Opus (and any unmeasurable codec, as before) uses
    /// <see cref="OpusPacketizer"/>; G.711 and G.722 use <see cref="OctetAudioPacketizer"/>, because their
    /// payload bytes are sample data and carry no Opus TOC.
    /// </summary>
    /// <returns>A new packetizer with its own talkspurt state.</returns>
    internal IRtpPayloadizer CreatePacketizer() => _codec is Codec.Pcm or Codec.G722
        ? new OctetAudioPacketizer(_rtpClockRate)
        : new OpusPacketizer();

    /// <summary>True when the codec is one we can measure (opus, PCMU, PCMA, G722).</summary>
    internal bool IsKnown => _codec != Codec.Unknown;

    /// <summary>The audio sample rate in Hz that <see cref="GetSamples"/> counts in; 0 when unknown.</summary>
    internal int SampleRate => _codec switch
    {
        Codec.Opus => (int)OpusSampleRate,
        Codec.Pcm => (int)_rtpClockRate,

        // G.722 runs its RTP clock at 8 kHz while sampling at 16 kHz.
        Codec.G722 => 2 * (int)_rtpClockRate,
        _ => 0,
    };

    /// <summary>Audio samples the payload covers at <see cref="SampleRate"/>; -1 when unknown.</summary>
    /// <param name="payload">One audio RTP payload.</param>
    /// <returns>The sample count, or <see cref="OutboundCutResult.UnknownSamples"/> when the codec is unknown.</returns>
    internal long GetSamples(ReadOnlySpan<byte> payload) => _codec switch
    {
        // Unchanged from the 0.5.0 formula: the duration comes from the Opus TOC byte (RFC 6716 §3.1).
        Codec.Opus => OpusPacketizer.GetDurationMicroseconds(payload) * OpusSampleRate / 1_000_000,

        // One sample per octet, mono (RFC 3551 §4.5.14).
        Codec.Pcm => payload.Length,

        // Two samples per octet (RFC 3551 §4.5.2).
        Codec.G722 => 2L * payload.Length,
        _ => OutboundCutResult.UnknownSamples,
    };

    /// <summary>RTP timestamp ticks the payload covers; false (ticks = 0) when unknown.</summary>
    /// <param name="payload">One audio RTP payload.</param>
    /// <param name="ticks">On success, the RTP timestamp increment for the payload.</param>
    /// <returns>True when the codec can be measured.</returns>
    internal bool TryGetRtpTicks(ReadOnlySpan<byte> payload, out uint ticks)
    {
        switch (_codec)
        {
            case Codec.Opus:
                // RFC 7587 §4.1: the RTP clock is 48 kHz, so ticks equal the 48 kHz sample count.
                ticks = (uint)(OpusPacketizer.GetDurationMicroseconds(payload) * OpusSampleRate / 1_000_000);
                return true;
            case Codec.Pcm:
                // One sample per octet at the RTP clock rate.
                ticks = (uint)payload.Length;
                return true;
            case Codec.G722:
                // One RTP tick per payload octet on the 8 kHz clock (two 16 kHz audio samples).
                ticks = (uint)payload.Length;
                return true;
            default:
                ticks = 0;
                return false;
        }
    }
}
