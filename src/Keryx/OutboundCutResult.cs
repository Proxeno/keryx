namespace Keryx;

/// <summary>What one outbound-audio cut discarded (see <see cref="PeerConnection.CutOutboundAudio"/>).</summary>
/// <param name="PacketsDiscarded">Queued RTP packets dropped before they reached the wire.</param>
/// <param name="SamplesDiscarded">
/// Their total media duration counted in audio samples at <see cref="SampleRate"/>, which is NOT
/// necessarily the RTP clock rate: G.722 is 16000 Hz samples on an 8000 Hz RTP clock. Opus counts from
/// each packet's TOC byte at 48 kHz (unchanged from 0.5.0); PCMU/PCMA count one sample per payload
/// byte; G.722 counts two samples per payload byte. For any other codec this is
/// <see cref="UnknownSamples"/> (-1) when at least one packet was discarded and 0 when none was — never
/// a guessed number. Prefer <see cref="DurationDiscarded"/> for codec-independent use.
/// </param>
public readonly record struct OutboundCutResult(int PacketsDiscarded, long SamplesDiscarded)
{
    /// <summary>The value of <see cref="SamplesDiscarded"/> when packets were discarded but the codec cannot be measured.</summary>
    public const long UnknownSamples = -1;

    /// <summary>
    /// The Hz that <see cref="SamplesDiscarded"/> is counted in: 48000 Opus, 8000 PCMU/PCMA, 16000 G.722;
    /// 0 when the codec is not one of those.
    /// </summary>
    public int SampleRate { get; init; }

    /// <summary>
    /// The output generation this cut started (see <see cref="RtpPacketSentInfo.Generation"/>); 0 when no
    /// track was streaming.
    /// </summary>
    public int Generation { get; init; }

    /// <summary>Media time discarded; <see langword="null"/> when unknown.</summary>
    public TimeSpan? DurationDiscarded =>
        SamplesDiscarded == 0 ? TimeSpan.Zero
        : SamplesDiscarded < 0 || SampleRate <= 0 ? null
        : TimeSpan.FromTicks(SamplesDiscarded * TimeSpan.TicksPerSecond / SampleRate);
}
