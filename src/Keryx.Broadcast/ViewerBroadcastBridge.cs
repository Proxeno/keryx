using System.Net;
using Keryx.Rtp.Simulcast;
using Keryx.Srtp;

namespace Keryx.Broadcast;

/// <summary>
/// The per-viewer key-bridge (<c>broadcast-scale.md</c> §4): turns a live <see cref="ViewerSession"/> —
/// a real viewer that completed its own ICE + DTLS handshake and negotiated its own DTLS-derived SRTP
/// keys — into a <see cref="BroadcastSubscriber"/> on the parallel fan-out fast path, encrypting that
/// viewer's media under <b>the viewer's own key</b> to <b>the viewer's own destination</b>.
/// </summary>
/// <remarks>
/// <para>
/// Without the bridge a browser viewer can only be served over the per-datagram
/// <c>PeerConnection.TryForwardRtp</c> path, because its send key was derived from its DTLS handshake and
/// lives inside its <see cref="PeerConnection"/>. The bridge sources that key as an opaque, send-keyed
/// <see cref="SrtpEncryptContext"/> (<see cref="PeerConnection.CreateSendKeyedSrtpContext"/> — no key
/// bytes are exposed) and pairs it with the viewer's ICE-bound 5-tuple, so the viewer can instead ride
/// <c>BroadcastFanout</c> → <c>BroadcastEndpoint.SendBatch</c> → <c>sendmmsg</c>: parallel per-viewer
/// encrypt, one batched flush, still byte-correct under the key the viewer's browser already holds.
/// </para>
/// <para>
/// <b>Ownership and the one-owner rule.</b> The bridged subscriber holds a fresh encrypt context that
/// shares the connection's send master key. Two independent SRTP packet indices over one key+SSRC would
/// repeat AES-CM keystream / AEAD nonces, so once a viewer is bridged its media must flow <i>only</i>
/// through the fan-out: do not also call <see cref="PeerConnection.TryForwardRtp"/> on that connection for
/// the bridged SSRC. RTCP the connection still emits on its own context is a distinct SRTP keyspace and
/// does not conflict. The returned subscriber owns its encrypt context and disposes it on
/// <see cref="BroadcastSubscriber.Dispose"/>.
/// </para>
/// </remarks>
public static class ViewerBroadcastBridge
{
    /// <summary>
    /// Builds a fan-out subscriber for <paramref name="session"/> keyed to that viewer's negotiated SRTP
    /// send direction and addressed to its bound 5-tuple. The caller supplies the
    /// <paramref name="forwarder"/> — and with it the broadcast SSRC / payload type / selected layer — so
    /// the viewer can be placed on any tier; the bridge only wires in the viewer's key and destination.
    /// </summary>
    /// <param name="session">A connected viewer session (ICE + DTLS complete, 5-tuple bound).</param>
    /// <param name="forwarder">
    /// The subscriber's rewrite primitive; its layer must already be selected
    /// (<see cref="RtpForwarder.SelectLayer"/>). Its <see cref="RtpForwarder.OutboundSsrc"/> must be an
    /// SSRC the connection does not itself send RTP on via <see cref="PeerConnection.TryForwardRtp"/> (see
    /// the type remarks on the one-owner rule).
    /// </param>
    /// <param name="maxIngestPacketSize">
    /// The largest ingest RTP packet the subscriber sizes its reusable buffers for.
    /// </param>
    /// <returns>A fan-out subscriber encrypting under the viewer's own key to the viewer's own endpoint.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="session"/> or <paramref name="forwarder"/> is null.</exception>
    /// <exception cref="InvalidOperationException">
    /// The viewer has not negotiated SRTP yet (DTLS incomplete), or its ICE 5-tuple has not bound yet.
    /// </exception>
    public static BroadcastSubscriber CreateFanoutSubscriber(
        ViewerSession session,
        RtpForwarder forwarder,
        int maxIngestPacketSize = BroadcastSubscriber.DefaultMaxIngestPacketSize)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(forwarder);

        var destination = session.PrimaryDestination
            ?? throw new InvalidOperationException(
                $"Viewer session '{session.Id}' has no bound 5-tuple yet; wait for it to connect (its first "
                + "STUN check binds the destination) before bridging it onto the broadcast fan-out.");

        // Mint a fresh encrypt context keyed to this viewer's DTLS-derived send direction. Throws if SRTP is
        // not negotiated yet. Owned by the subscriber from here on; dispose it if wiring the subscriber fails.
        var srtp = session.Connection.CreateSendKeyedSrtpContext();
        try
        {
            return new BroadcastSubscriber(forwarder, srtp, destination, maxIngestPacketSize);
        }
        catch
        {
            srtp.Dispose();
            throw;
        }
    }
}
