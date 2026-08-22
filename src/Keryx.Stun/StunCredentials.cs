using System.Security.Cryptography;
using System.Text;

namespace Keryx.Stun;

/// <summary>
/// Derives the HMAC-SHA1 keys used by the MESSAGE-INTEGRITY attribute (RFC 5389 section 15.4).
/// </summary>
/// <remarks>
/// <para>
/// RFC 5389 requires usernames, passwords and realms to be run through SASLprep (RFC 4013) before
/// keying. Keryx does not implement SASLprep: the strings are UTF-8 encoded as supplied. For the
/// ASCII ICE credentials used by WebRTC (RFC 8445 restricts ufrag/pwd to <c>ice-char</c>) SASLprep
/// is the identity function, so this is exact. Callers using non-ASCII long-term credentials must
/// SASLprep the values themselves before calling <see cref="LongTermKey"/>.
/// </para>
/// </remarks>
public static class StunCredentials
{
    /// <summary>
    /// Short-term credential key: the SASLprep-processed password, UTF-8 encoded
    /// (RFC 5389 section 15.4). This is the keying ICE connectivity checks use.
    /// </summary>
    /// <param name="password">The already-SASLprep-processed password.</param>
    /// <returns>The HMAC key.</returns>
    public static byte[] ShortTermKey(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        return Encoding.UTF8.GetBytes(password);
    }

    /// <summary>
    /// Long-term credential key: <c>MD5(username ":" realm ":" password)</c> over the
    /// SASLprep-processed, UTF-8 encoded parts (RFC 5389 section 15.4).
    /// </summary>
    /// <param name="username">The already-SASLprep-processed username.</param>
    /// <param name="realm">The realm.</param>
    /// <param name="password">The already-SASLprep-processed password.</param>
    /// <returns>The 16-byte HMAC key.</returns>
    public static byte[] LongTermKey(string username, string realm, string password)
    {
        ArgumentNullException.ThrowIfNull(username);
        ArgumentNullException.ThrowIfNull(realm);
        ArgumentNullException.ThrowIfNull(password);

        var input = Encoding.UTF8.GetBytes($"{username}:{realm}:{password}");
        return MD5.HashData(input);
    }
}
