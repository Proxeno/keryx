using System.Net;
using Keryx.Sdp;

namespace Keryx.IntegrationTests;

/// <summary>
/// Shared helpers for the voice-agent session shape: one <c>sendrecv</c> Opus audio m-line, one SCTP
/// (<c>m=application</c>) m-line, and no video. The legacy audio transceiver is built sendonly, so the
/// side that builds an offer or answer flips it to <see cref="MediaDirection.SendRecv"/> first (the
/// answering side must do so after applying the offer, because binding a legacy transceiver resets its
/// direction to the complement of what was offered).
/// </summary>
internal static class VoiceTestSupport
{
    /// <summary>A valid three-byte Opus silence packet (frame size 20 ms, 48 kHz).</summary>
    internal static readonly byte[] OpusSilence = [0xF8, 0xFF, 0xFE];

    /// <summary>A config with the default Opus audio codec and no video codecs at all.</summary>
    /// <param name="bindAddress">The interface to bind; null keeps the loopback interface.</param>
    /// <returns>The voice-shaped config.</returns>
    internal static PeerConnectionConfig NewVoiceConfig(IPAddress? bindAddress = null)
    {
        var config = TestSupport.NewConfig(bindAddress: bindAddress);
        config.VideoCodecs.Clear();
        return config;
    }

    /// <summary>The peer's audio transceiver — the only transceiver in a voice-shaped session.</summary>
    /// <param name="peer">The connection.</param>
    /// <returns>The audio transceiver.</returns>
    internal static RtpTransceiver Audio(PeerConnection peer) =>
        peer.Transceivers.Single(static t => t.Kind == MediaKind.Audio);

    /// <summary>Makes this side's audio m-line bidirectional before it builds the next description.</summary>
    /// <param name="peer">The connection.</param>
    internal static void MakeAudioSendRecv(PeerConnection peer) =>
        Audio(peer).Direction = MediaDirection.SendRecv;

    /// <summary>Wires trickled candidates between two peers in both directions.</summary>
    /// <param name="a">The first peer.</param>
    /// <param name="b">The second peer.</param>
    internal static void WireCandidates(PeerConnection a, PeerConnection b)
    {
        a.OnLocalIceCandidate += (_, e) => b.AddIceCandidate(e.Candidate, e.SdpMid);
        b.OnLocalIceCandidate += (_, e) => a.AddIceCandidate(e.Candidate, e.SdpMid);
    }
}
