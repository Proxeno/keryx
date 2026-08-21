using System.Security.Cryptography;
using System.Text;

namespace Keryx.Dtls;

/// <summary>
/// The TLS 1.2 pseudo-random function (RFC 5246 §5) specialised to <c>P_SHA256</c>, which is the
/// PRF for every cipher suite Keryx implements.
/// </summary>
/// <remarks>
/// The protocol construction is implemented here; the underlying HMAC-SHA256 primitive comes from
/// <see cref="HMACSHA256"/>. Keryx never hand-rolls a hash or a cipher.
/// </remarks>
internal static class TlsPrf
{
    public const string MasterSecretLabel = "master secret";
    public const string ExtendedMasterSecretLabel = "extended master secret";
    public const string KeyExpansionLabel = "key expansion";
    public const string ClientFinishedLabel = "client finished";
    public const string ServerFinishedLabel = "server finished";

    /// <summary>Length of the TLS master secret in bytes.</summary>
    public const int MasterSecretLength = 48;

    private const int HashLength = 32;

    /// <summary>
    /// <c>PRF(secret, label, seed) = P_SHA256(secret, label || seed)</c>, truncated to
    /// <paramref name="length"/> bytes.
    /// </summary>
    public static byte[] Prf(ReadOnlySpan<byte> secret, string label, ReadOnlySpan<byte> seed, int length)
    {
        ArgumentNullException.ThrowIfNull(label);
        ArgumentOutOfRangeException.ThrowIfNegative(length);

        var labelLength = Encoding.ASCII.GetByteCount(label);
        var combined = new byte[labelLength + seed.Length];
        Encoding.ASCII.GetBytes(label, combined);
        seed.CopyTo(combined.AsSpan(labelLength));

        var result = new byte[length];
        PHashSha256(secret, combined, result);
        CryptographicOperations.ZeroMemory(combined);
        return result;
    }

    /// <summary>
    /// <c>P_SHA256</c> from RFC 5246 §5:
    /// <c>P_hash(secret, seed) = HMAC(secret, A(1) || seed) || HMAC(secret, A(2) || seed) || ...</c>
    /// where <c>A(0) = seed</c> and <c>A(i) = HMAC(secret, A(i - 1))</c>.
    /// </summary>
    public static void PHashSha256(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> seed, Span<byte> destination)
    {
        if (destination.Length == 0)
        {
            return;
        }

        Span<byte> a = stackalloc byte[HashLength];
        Span<byte> next = stackalloc byte[HashLength];
        Span<byte> block = stackalloc byte[HashLength];

        // A(1) = HMAC(secret, A(0)) with A(0) = seed.
        HMACSHA256.HashData(secret, seed, a);

        var input = new byte[HashLength + seed.Length];
        seed.CopyTo(input.AsSpan(HashLength));

        var offset = 0;
        while (offset < destination.Length)
        {
            a.CopyTo(input);
            HMACSHA256.HashData(secret, input, block);

            var take = Math.Min(HashLength, destination.Length - offset);
            block[..take].CopyTo(destination[offset..]);
            offset += take;

            if (offset < destination.Length)
            {
                HMACSHA256.HashData(secret, a, next);
                next.CopyTo(a);
            }
        }

        CryptographicOperations.ZeroMemory(input);
        CryptographicOperations.ZeroMemory(a);
        CryptographicOperations.ZeroMemory(next);
        CryptographicOperations.ZeroMemory(block);
    }

    /// <summary>Standard master secret derivation (RFC 5246 §8.1).</summary>
    public static byte[] MasterSecret(
        ReadOnlySpan<byte> preMasterSecret,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom)
    {
        Span<byte> seed = stackalloc byte[clientRandom.Length + serverRandom.Length];
        clientRandom.CopyTo(seed);
        serverRandom.CopyTo(seed[clientRandom.Length..]);
        return Prf(preMasterSecret, MasterSecretLabel, seed, MasterSecretLength);
    }

    /// <summary>Extended master secret derivation over the session hash (RFC 7627 §4).</summary>
    public static byte[] ExtendedMasterSecret(ReadOnlySpan<byte> preMasterSecret, ReadOnlySpan<byte> sessionHash) =>
        Prf(preMasterSecret, ExtendedMasterSecretLabel, sessionHash, MasterSecretLength);

    /// <summary>
    /// Key block expansion (RFC 5246 §6.3). Note the seed order is <c>server_random || client_random</c>,
    /// the reverse of the master secret seed.
    /// </summary>
    public static byte[] KeyBlock(
        ReadOnlySpan<byte> masterSecret,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom,
        int length)
    {
        Span<byte> seed = stackalloc byte[serverRandom.Length + clientRandom.Length];
        serverRandom.CopyTo(seed);
        clientRandom.CopyTo(seed[serverRandom.Length..]);
        return Prf(masterSecret, KeyExpansionLabel, seed, length);
    }

    /// <summary>Finished <c>verify_data</c> (RFC 5246 §7.4.9).</summary>
    public static byte[] VerifyData(ReadOnlySpan<byte> masterSecret, string label, ReadOnlySpan<byte> transcriptHash) =>
        Prf(masterSecret, label, transcriptHash, DtlsLimits.VerifyDataLength);

    /// <summary>
    /// RFC 5705 keying material exporter with no context value, as required by DTLS-SRTP
    /// (RFC 5764 §4.2). The seed is <c>client_random || server_random</c>.
    /// </summary>
    public static byte[] ExportKeyingMaterial(
        ReadOnlySpan<byte> masterSecret,
        string label,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom,
        int length)
    {
        Span<byte> seed = stackalloc byte[clientRandom.Length + serverRandom.Length];
        clientRandom.CopyTo(seed);
        serverRandom.CopyTo(seed[clientRandom.Length..]);
        return Prf(masterSecret, label, seed, length);
    }
}
