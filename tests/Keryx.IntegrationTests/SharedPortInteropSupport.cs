using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using FluentAssertions;
using Keryx.Broadcast;
using Keryx.Rtp;
using Keryx.Sdp;

namespace Keryx.IntegrationTests;

/// <summary>
/// Shared plumbing for the shared-port interop lanes: a real peer (Chrome, Firefox, pion) connects to a
/// <see cref="BroadcastEndpoint"/> — a 2-socket <c>SO_REUSEPORT</c> pool on Linux — while a plain Keryx
/// "companion" viewer is already connected to the same port, so the port is genuinely shared by two
/// sessions while the real peer handshakes.
/// </summary>
internal static class SharedPortInteropSupport
{
    /// <summary>The requested socket pool size; the effective size is 1 off Linux.</summary>
    internal const int PoolSize = 2;

    private const int CompanionTag = 7777;
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Creates a loopback-bound endpoint, or (<paramref name="wildcard"/>) a wildcard-bound one that
    /// advertises the default-route address — what headless Firefox binds.
    /// </summary>
    /// <param name="wildcard">True to bind <see cref="IPAddress.Any"/> and advertise <see cref="DefaultRouteAddress"/>.</param>
    /// <returns>The endpoint.</returns>
    internal static BroadcastEndpoint CreateEndpoint(bool wildcard)
    {
        var options = new BroadcastEndpointOptions
        {
            SocketPoolSize = PoolSize,
            MaxViewers = 4,
        };

        if (wildcard)
        {
            options.BindEndPoint = new IPEndPoint(IPAddress.Any, 0);
            options.AdvertisedAddress = DefaultRouteAddress();
        }
        else
        {
            options.BindEndPoint = new IPEndPoint(IPAddress.Loopback, 0);
        }

        return new BroadcastEndpoint(options);
    }

    /// <summary>
    /// The default-route interface address: a UDP socket connected to TEST-NET-1 (nothing is sent) reports
    /// the local address the OS would use. Falls back to the first up, non-loopback IPv4 unicast address,
    /// then loopback.
    /// </summary>
    /// <returns>The address.</returns>
    internal static IPAddress DefaultRouteAddress()
    {
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Connect(new IPEndPoint(IPAddress.Parse("192.0.2.1"), 9));
            if (socket.LocalEndPoint is IPEndPoint { Address: var address } && !address.Equals(IPAddress.Any))
            {
                return address;
            }
        }
        catch (SocketException)
        {
            // fall through to the interface scan
        }

        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }

            foreach (var unicast in nic.GetIPProperties().UnicastAddresses)
            {
                if (unicast.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(unicast.Address))
                {
                    return unicast.Address;
                }
            }
        }

        return IPAddress.Loopback;
    }

    /// <summary>
    /// Connects a plain Keryx viewer to <paramref name="endpoint"/> (mirrors
    /// <c>BroadcastSocketPoolTests.ConnectViewerAsync</c>) so the shared port carries two sessions.
    /// </summary>
    /// <param name="endpoint">The shared endpoint.</param>
    /// <param name="wildcard">True when the endpoint is wildcard-bound (the companion then binds any too).</param>
    /// <param name="cancellationToken">Bounds the handshake.</param>
    /// <returns>The connected companion.</returns>
    internal static async Task<Companion> ConnectCompanionAsync(
        BroadcastEndpoint endpoint,
        bool wildcard,
        CancellationToken cancellationToken)
    {
        var viewer = new PeerConnection(TestSupport.NewConfig(bindAddress: wildcard ? IPAddress.Any : null));
        try
        {
            var session = endpoint.AddViewer(TestSupport.NewConfig());
            var egress = session.Connection;

            var tags = new ConcurrentQueue<int>();
            var distinct = new ConcurrentDictionary<int, byte>();
            viewer.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
            {
                if (info.Kind != MediaKind.Video || payload.Length < 8)
                {
                    return;
                }

                tags.Enqueue(BinaryPrimitives.ReadInt32BigEndian(payload));
                distinct.TryAdd(BinaryPrimitives.ReadInt32BigEndian(payload[4..]), 0);
            };

            viewer.OnLocalIceCandidate += (_, e) => egress.AddIceCandidate(e.Candidate, e.SdpMid);
            egress.OnLocalIceCandidate += (_, e) => viewer.AddIceCandidate(e.Candidate, e.SdpMid);

            var offer = await viewer.CreateOfferAsync(cancellationToken);
            var recvonlyOffer = offer.Replace("a=sendonly", "a=recvonly", StringComparison.Ordinal);
            await egress.SetRemoteDescriptionAsync(recvonlyOffer, SdpType.Offer, cancellationToken);
            var answer = await egress.CreateAnswerAsync(cancellationToken);
            await viewer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

            (await egress.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue(
                "the companion viewer's egress must connect over the shared port");
            (await viewer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue(
                "the companion viewer must connect over the shared port");

            return new Companion(viewer, session, tags, distinct);
        }
        catch
        {
            await viewer.DisposeAsync();
            throw;
        }
    }

    /// <summary>
    /// Forwards <paramref name="packets"/> tagged packets to the companion and asserts it received all of
    /// them, and only its own tag. Call after the real peer has received media so it proves the companion
    /// was undisturbed.
    /// </summary>
    /// <param name="companion">The companion viewer.</param>
    /// <param name="packets">How many packets to forward.</param>
    /// <param name="cancellationToken">Bounds the forwarding.</param>
    /// <returns>A task that completes when the assertions hold.</returns>
    internal static async Task AssertCompanionStillReceivesAsync(Companion companion, int packets, CancellationToken cancellationToken)
    {
        var egress = companion.Session.Connection;
        var payloadType = egress.GetNegotiatedPayloadType(MediaKind.Video);
        payloadType.Should().NotBeNull("the companion negotiated a video track");

        for (var packetIndex = 0; packetIndex < packets; packetIndex++)
        {
            var payload = new byte[64];
            BinaryPrimitives.WriteInt32BigEndian(payload, CompanionTag);
            BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(4), packetIndex);

            var marker = packetIndex == packets - 1;
            egress.TryForwardRtp(MediaKind.Video, payload, 5_000_000u + ((uint)packetIndex * 3000u), marker, payloadType!.Value)
                .Should().BeTrue();
            await Task.Delay(3, cancellationToken);
        }

        (await TestSupport.WaitForAsync(() => companion.DistinctIndices.Count >= packets)).Should().BeTrue(
            "the companion viewer must keep receiving its whole stream while the real peer shares the port");
        companion.ReceivedTags.Should().OnlyContain(
            tag => tag == CompanionTag,
            "the companion must only ever see media addressed to its own session");
    }

    /// <summary>Asserts the pool shape: <see cref="PoolSize"/> sockets on Linux, one elsewhere.</summary>
    /// <param name="endpoint">The endpoint to check.</param>
    internal static void AssertPoolShape(BroadcastEndpoint endpoint)
    {
        if (OperatingSystem.IsLinux())
        {
            endpoint.SocketPoolSize.Should().Be(PoolSize, "SO_REUSEPORT lets the pool bind one port on Linux");
        }
        else
        {
            endpoint.SocketPoolSize.Should().Be(1, "the endpoint falls back to a single socket without SO_REUSEPORT");
        }
    }

    /// <summary>A plain Keryx viewer on the shared endpoint and what it has received.</summary>
    internal sealed class Companion : IAsyncDisposable
    {
        private readonly PeerConnection _viewer;

        internal Companion(
            PeerConnection viewer,
            ViewerSession session,
            ConcurrentQueue<int> receivedTags,
            ConcurrentDictionary<int, byte> distinctIndices)
        {
            _viewer = viewer;
            Session = session;
            ReceivedTags = receivedTags;
            DistinctIndices = distinctIndices;
        }

        /// <summary>The endpoint-side session.</summary>
        internal ViewerSession Session { get; }

        /// <summary>Every payload tag the companion received.</summary>
        internal ConcurrentQueue<int> ReceivedTags { get; }

        /// <summary>The distinct packet indices the companion received.</summary>
        internal ConcurrentDictionary<int, byte> DistinctIndices { get; }

        /// <inheritdoc />
        public ValueTask DisposeAsync() => _viewer.DisposeAsync();
    }
}
