using System.Security.Cryptography;
using System.Text;

namespace Keryx.Stun;

/// <summary>
/// A long-term credential key-derivation algorithm from the IANA STUN Password Algorithms registry
/// (RFC 8489 section 18.5.1). Both registered algorithms take no parameters.
/// </summary>
public enum StunPasswordAlgorithm : ushort
{
    /// <summary>MD5: <c>key = MD5(username ":" realm ":" password)</c> (RFC 8489 sections 9.2.2 and 18.5.1).</summary>
    Md5 = 0x0001,

    /// <summary>SHA-256: <c>key = SHA-256(username ":" realm ":" password)</c> (RFC 8489 sections 9.2.2 and 18.5.1).</summary>
    Sha256 = 0x0002,
}

/// <summary>
/// Derives the HMAC-SHA1 keys used by the MESSAGE-INTEGRITY attribute (RFC 5389 section 15.4).
/// </summary>
/// <remarks>
/// <para>
/// RFC 5389 requires usernames, passwords and realms to be run through SASLprep (RFC 4013) before
/// keying. Keryx does not implement SASLprep: the strings are UTF-8 encoded as supplied. For the
/// ASCII ICE credentials used by WebRTC (RFC 8445 restricts ufrag/pwd to <c>ice-char</c>) SASLprep
/// is the identity function, so this is exact. Callers using non-ASCII long-term credentials must
/// SASLprep the values themselves before calling <see cref="LongTermKey(string, string, string)"/>.
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
    /// SASLprep-processed, UTF-8 encoded parts (RFC 5389 section 15.4). Equivalent to
    /// <see cref="LongTermKey(string, string, string, StunPasswordAlgorithm)"/> with
    /// <see cref="StunPasswordAlgorithm.Md5"/>.
    /// </summary>
    /// <param name="username">The already-SASLprep-processed username.</param>
    /// <param name="realm">The realm.</param>
    /// <param name="password">The already-SASLprep-processed password.</param>
    /// <returns>The 16-byte HMAC key.</returns>
    public static byte[] LongTermKey(string username, string realm, string password)
        => LongTermKey(username, realm, password, StunPasswordAlgorithm.Md5);

    /// <summary>
    /// Long-term credential key under an explicit RFC 8489 password algorithm: MD5 gives the
    /// RFC 5389 key, SHA-256 gives <c>SHA-256(username ":" realm ":" password)</c>
    /// (RFC 8489 sections 9.2.2 and 18.5.1). The negotiated algorithm also selects which digest
    /// - MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 - the key is used with; that pairing is the
    /// caller's responsibility, not this method's.
    /// </summary>
    /// <param name="username">The already-SASLprep-processed username.</param>
    /// <param name="realm">The realm.</param>
    /// <param name="password">The already-SASLprep-processed password.</param>
    /// <param name="algorithm">The password algorithm to derive the key with.</param>
    /// <returns>The 16-byte (MD5) or 32-byte (SHA-256) key.</returns>
    public static byte[] LongTermKey(string username, string realm, string password, StunPasswordAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(username);
        ArgumentNullException.ThrowIfNull(realm);
        ArgumentNullException.ThrowIfNull(password);

        var input = Encoding.UTF8.GetBytes($"{username}:{realm}:{password}");
        return algorithm switch
        {
            StunPasswordAlgorithm.Md5 => MD5.HashData(input),
            StunPasswordAlgorithm.Sha256 => SHA256.HashData(input),
            _ => throw new ArgumentOutOfRangeException(
                nameof(algorithm), algorithm, $"Keryx does not implement the RFC 8489 password algorithm {(ushort)algorithm}."),
        };
    }
}
