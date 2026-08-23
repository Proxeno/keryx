using System.Net;

namespace Keryx.Ice;

/// <summary>
/// Resolves an mDNS <c>&lt;name&gt;.local</c> host name (draft-ietf-mmusic-mdns-ice-candidates) to
/// a transport address, so an obfuscated remote host candidate can be paired instead of dropped.
/// </summary>
/// <remarks>
/// Implementations must not throw for an ordinary "not found" outcome: a name that no responder
/// answers within the deadline is signalled by returning <see langword="null"/>, which the
/// <see cref="IceAgent"/> logs and skips. The seam is an interface so a test can route candidate
/// intake through a stub without a live multicast responder; <see cref="MulticastMdnsResolver"/> is
/// the production implementation.
/// </remarks>
public interface IMdnsResolver
{
    /// <summary>Resolves <paramref name="hostName"/>, or returns null when it cannot be resolved in time.</summary>
    /// <param name="hostName">The <c>.local</c> host name to resolve.</param>
    /// <param name="cancellationToken">Bounds the wait; a cancelled token yields null, not an exception from the caller's view.</param>
    /// <returns>The resolved address, or null on timeout or failure.</returns>
    Task<IPAddress?> ResolveAsync(string hostName, CancellationToken cancellationToken = default);
}
