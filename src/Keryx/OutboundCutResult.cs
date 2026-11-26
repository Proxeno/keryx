namespace Keryx;

/// <summary>What one outbound-audio cut discarded (see <see cref="PeerConnection.CutOutboundAudio"/>).</summary>
/// <param name="PacketsDiscarded">Queued RTP packets dropped before they reached the wire.</param>
/// <param name="SamplesDiscarded">
/// Their total duration in samples at the RTP clock rate (48 kHz for Opus), from each Opus packet's TOC byte.
/// </param>
public readonly record struct OutboundCutResult(int PacketsDiscarded, long SamplesDiscarded);
