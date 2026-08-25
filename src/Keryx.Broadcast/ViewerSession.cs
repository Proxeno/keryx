using System.Net;

namespace Keryx.Broadcast;

/// <summary>
/// One viewer's state on a <see cref="BroadcastEndpoint"/>: the viewer's server-side
/// <see cref="PeerConnection"/> (its ICE agent in endpoint-session mode, its own DTLS handshake and
/// per-viewer SRTP keys), riding the shared socket through the endpoint's send seam and fed inbound
/// datagrams the endpoint demultiplexes to it by 5-tuple (<c>broadcast-scale.md</c> §2).
/// </summary>
/// <remarks>
/// A session is single-owner state: everything per-viewer — ICE session, DTLS, SRTP, forwarder — lives
/// here, and the only objects shared across viewers are the socket and the endpoint's demux maps. That
/// isolation is what lets §4 later place each session on exactly one shard with no per-viewer locking;
/// here it means one viewer's teardown never touches another's.
/// </remarks>
public sealed class ViewerSession
{
    private readonly object _lock = new();
    private readonly List<IPEndPoint> _boundEndPoints = [];
    private object? _sharedKeyTier;

    internal ViewerSession(string id, PeerConnection connection, string localIceUfrag)
    {
        Id = id;
        Connection = connection;
        LocalIceUfrag = localIceUfrag;
    }

    /// <summary>A stable identifier for this session, unique within its endpoint.</summary>
    public string Id { get; }

    /// <summary>
    /// The viewer's server-side connection. The caller drives SDP negotiation and media on it (offer
    /// exchange, forwarding RTP); the endpoint owns only its transport.
    /// </summary>
    public PeerConnection Connection { get; }

    /// <summary>
    /// The local ICE ufrag this session answers with. A viewer's first STUN Binding request names it
    /// in the USERNAME attribute (<c>{local-ufrag}:{remote-ufrag}</c>), which is how the endpoint
    /// binds that first 5-tuple to this session.
    /// </summary>
    public string LocalIceUfrag { get; }

    /// <summary>The remote 5-tuples currently routed to this session; snapshot, for diagnostics.</summary>
    public IReadOnlyList<IPEndPoint> BoundEndPoints
    {
        get
        {
            lock (_lock)
            {
                return [.. _boundEndPoints];
            }
        }
    }

    internal void Inject(ReadOnlySpan<byte> datagram, IPEndPoint from) => Connection.InjectIceDatagram(datagram, from);

    internal void NoteBoundEndPoint(IPEndPoint endPoint)
    {
        lock (_lock)
        {
            if (!_boundEndPoints.Contains(endPoint))
            {
                _boundEndPoints.Add(endPoint);
            }
        }
    }

    internal IReadOnlyList<IPEndPoint> DrainBoundEndPoints()
    {
        lock (_lock)
        {
            var snapshot = _boundEndPoints.ToArray();
            _boundEndPoints.Clear();
            return snapshot;
        }
    }

    internal void CopyBoundEndPointsTo(List<IPEndPoint> destination)
    {
        lock (_lock)
        {
            destination.AddRange(_boundEndPoints);
        }
    }

    // Claims this session for exactly one shared-key broadcast tier (spec §5.4 invariant: a session is
    // never enrolled into two different broadcasts' shared keys). Returns true if the session is now
    // owned by <paramref name="tier"/> (either freshly claimed or already claimed by it); false if it is
    // already claimed by a different tier.
    internal bool TryClaimSharedKeyTier(object tier)
    {
        lock (_lock)
        {
            if (_sharedKeyTier is null || ReferenceEquals(_sharedKeyTier, tier))
            {
                _sharedKeyTier = tier;
                return true;
            }

            return false;
        }
    }

    internal void ReleaseSharedKeyTier(object tier)
    {
        lock (_lock)
        {
            if (ReferenceEquals(_sharedKeyTier, tier))
            {
                _sharedKeyTier = null;
            }
        }
    }
}
