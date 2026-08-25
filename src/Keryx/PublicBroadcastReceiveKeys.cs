using Keryx.Core;
using Keryx.Srtp;

namespace Keryx.Broadcast;

/// <summary>
/// The receive-side installation of one or more <see cref="PublicBroadcastKey"/> exports on a viewer
/// connection: the shared-key SRTP decrypt context(s) used to unprotect the broadcast, scoped to the
/// exact broadcast SSRC(s) the key applies to. Installed from
/// <see cref="PeerConnectionConfig.InstallPublicBroadcastReceiveKey"/> and consulted by the connection's
/// RTP receive path (spec §5.1, §5.3).
/// </summary>
/// <remarks>
/// <para>
/// <b>SSRC scoping is the structural client-side boundary.</b> The shared key is only ever tried for the
/// enumerated broadcast SSRCs; every other SSRC on the connection — including any private receive
/// m-line — stays on the connection's own DTLS-derived keys. A shared key can therefore never decrypt,
/// and its keyholder never forge into, a private m-line on the same transport (spec §5.3).
/// </para>
/// <para>
/// <b>Epoch handling.</b> A rotation installs a new context and keeps the immediately-previous one, so a
/// viewer decrypts across the switch even though SRTP carries no MKI to name the epoch (spec §5.1): the
/// receive path tries the current epoch first, then the previous. Superseded contexts are retained until
/// the whole install is disposed rather than freed mid-flight, so an in-flight packet never hits a
/// disposed context.
/// </para>
/// <para>
/// The hot path is lock-free: installs publish a new immutable snapshot via a volatile reference, and
/// the single-threaded RTP receive loop reads it once per packet. Installs (rare, from the data channel
/// thread) are serialised by a lock.
/// </para>
/// </remarks>
/// <summary>One <c>InstallPublicBroadcastReceiveKey</c> request recorded on a config: an exported key and
/// the broadcast SSRC scope it applies to.</summary>
internal sealed record PublicBroadcastReceiveKeyInstall(PublicBroadcastKeyExport Export, IReadOnlyList<uint> BroadcastSsrcs);

internal sealed class PublicBroadcastReceiveKeys : IDisposable
{
    /// <summary>The outcome of offering an inbound packet to the shared-key receive path.</summary>
    internal enum Outcome
    {
        /// <summary>The SSRC is not a broadcast SSRC; the caller should use its DTLS-derived keys.</summary>
        NotBroadcast,

        /// <summary>The packet was authenticated and decrypted under a shared key.</summary>
        Unprotected,

        /// <summary>The SSRC is a broadcast SSRC but no installed epoch authenticated the packet.</summary>
        Failed,
    }

    private sealed record Snapshot(
        HashSet<uint> Ssrcs,
        SrtpDecryptContext Current,
        SrtpDecryptContext? Previous);

    private readonly IKeryxLogger _logger;
    private readonly object _installLock = new();
    private readonly List<SrtpDecryptContext> _retained = [];
    private volatile Snapshot? _snapshot;
    private bool _disposed;

    internal PublicBroadcastReceiveKeys(IKeryxLogger logger) => _logger = logger;

    /// <summary>
    /// Installs (or rotates to) a shared broadcast key for the given SSRC scope. The current epoch, if
    /// any, becomes the previous epoch so decryption continues across the switch.
    /// </summary>
    internal void Install(PublicBroadcastKeyExport export, IReadOnlyList<uint> broadcastSsrcs)
    {
        ArgumentNullException.ThrowIfNull(export);
        ArgumentNullException.ThrowIfNull(broadcastSsrcs);
        if (broadcastSsrcs.Count == 0)
        {
            throw new ArgumentException("A broadcast receive key must be scoped to at least one SSRC.", nameof(broadcastSsrcs));
        }

        var context = new SrtpDecryptContext(export.Profile, export.ToSessionKeys(), _logger);
        lock (_installLock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            var existing = _snapshot;
            var ssrcs = existing is null ? [] : new HashSet<uint>(existing.Ssrcs);
            foreach (var ssrc in broadcastSsrcs)
            {
                ssrcs.Add(ssrc);
            }

            _retained.Add(context);
            _snapshot = new Snapshot(ssrcs, context, existing?.Current);
            _logger.Log(
                KeryxLogLevel.Debug,
                $"Installed public-broadcast receive key epoch {export.Epoch} for {broadcastSsrcs.Count} SSRC(s).");
        }
    }

    /// <summary>True when <paramref name="ssrc"/> is one of the installed broadcast SSRCs.</summary>
    internal bool HandlesSsrc(uint ssrc)
    {
        var snapshot = _snapshot;
        return snapshot is not null && snapshot.Ssrcs.Contains(ssrc);
    }

    /// <summary>
    /// Tries to unprotect a broadcast RTP packet under the installed shared key(s). Only called for an
    /// SSRC <see cref="HandlesSsrc"/> accepted; tries the current epoch, then the previous.
    /// </summary>
    internal Outcome TryUnprotectRtp(uint ssrc, ReadOnlySpan<byte> srtpPacket, Span<byte> output, out int length)
    {
        length = 0;
        var snapshot = _snapshot;
        if (snapshot is null || !snapshot.Ssrcs.Contains(ssrc))
        {
            return Outcome.NotBroadcast;
        }

        if (snapshot.Current.TryUnprotectRtp(srtpPacket, output, out length))
        {
            return Outcome.Unprotected;
        }

        if (snapshot.Previous is { } previous && previous.TryUnprotectRtp(srtpPacket, output, out length))
        {
            return Outcome.Unprotected;
        }

        return Outcome.Failed;
    }

    public void Dispose()
    {
        lock (_installLock)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _snapshot = null;
            foreach (var context in _retained)
            {
                context.Dispose();
            }

            _retained.Clear();
        }
    }
}
