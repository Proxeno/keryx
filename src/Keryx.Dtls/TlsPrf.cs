using System.Security.Cryptography;
using System.Text;

namespace Keryx.Dtls;

/// <summary>The hash a TLS 1.2 PRF instance is built on. SHA-256 for most suites; SHA-384 for the
/// AES-256-GCM suites (RFC 5289 §3.2).</summary>
internal enum PrfHash
{
    Sha256,
    Sha384,
}

/// <summary>
/// The TLS 1.2 pseudo-random function (RFC 5246 §5). Every suite Keryx implements uses either
/// <c>P_SHA256</c> or <c>P_SHA384</c>, selected per cipher suite.
/// </summary>
/// <remarks>
/// The protocol construction is implemented here; the underlying HMAC-SHA256/384 primitives come from
/// <see cref="HMACSHA256"/> and <see cref="HMACSHA384"/>. Keryx never hand-rolls a hash or a cipher.
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

    private const int Sha256Length = 32;
    private const int Sha384Length = 48;

    /// <summary>Maps a TLS <c>HashAlgorithm</c> code (RFC 5246 §7.4.1.4.1) to the PRF hash it selects.</summary>
    public static PrfHash FromHashAlgorithm(byte hashAlgorithm) => hashAlgorithm switch
    {
        HashAlgorithms.Sha384 => PrfHash.Sha384,
        _ => PrfHash.Sha256,
    };

    /// <summary>
    /// <c>PRF(secret, label, seed) = P_hash(secret, label || seed)</c>, truncated to
    /// <paramref name="length"/> bytes, where <c>P_hash</c> is chosen by <paramref name="hash"/>.
    /// </summary>
    public static byte[] Prf(
        ReadOnlySpan<byte> secret,
        string label,
        ReadOnlySpan<byte> seed,
        int length,
        PrfHash hash = PrfHash.Sha256)
    {
        ArgumentNullException.ThrowIfNull(label);
        ArgumentOutOfRangeException.ThrowIfNegative(length);

        var labelLength = Encoding.ASCII.GetByteCount(label);
        var combined = new byte[labelLength + seed.Length];
        Encoding.ASCII.GetBytes(label, combined);
        seed.CopyTo(combined.AsSpan(labelLength));

        var result = new byte[length];
        PHash(hash, secret, combined, result);
        CryptographicOperations.ZeroMemory(combined);
        return result;
    }

    /// <summary>
    /// <c>P_SHA256</c> from RFC 5246 §5. Retained as the historical name; equivalent to
    /// <see cref="PHash"/> with <see cref="PrfHash.Sha256"/>.
    /// </summary>
    public static void PHashSha256(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> seed, Span<byte> destination) =>
        PHash(PrfHash.Sha256, secret, seed, destination);

    /// <summary>
    /// <c>P_hash</c> from RFC 5246 §5:
    /// <c>P_hash(secret, seed) = HMAC(secret, A(1) || seed) || HMAC(secret, A(2) || seed) || ...</c>
    /// where <c>A(0) = seed</c> and <c>A(i) = HMAC(secret, A(i - 1))</c>.
    /// </summary>
    public static void PHash(PrfHash hash, ReadOnlySpan<byte> secret, ReadOnlySpan<byte> seed, Span<byte> destination)
    {
        if (destination.Length == 0)
        {
            return;
        }

        var hashLength = HashLength(hash);
        Span<byte> a = stackalloc byte[Sha384Length];
        Span<byte> next = stackalloc byte[Sha384Length];
        Span<byte> block = stackalloc byte[Sha384Length];
        a = a[..hashLength];
        next = next[..hashLength];
        block = block[..hashLength];

        // A(1) = HMAC(secret, A(0)) with A(0) = seed.
        HmacHashData(hash, secret, seed, a);

        var input = new byte[hashLength + seed.Length];
        seed.CopyTo(input.AsSpan(hashLength));

        var offset = 0;
        while (offset < destination.Length)
        {
            a.CopyTo(input);
            HmacHashData(hash, secret, input, block);

            var take = Math.Min(hashLength, destination.Length - offset);
            block[..take].CopyTo(destination[offset..]);
            offset += take;

            if (offset < destination.Length)
            {
                HmacHashData(hash, secret, a, next);
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
        ReadOnlySpan<byte> serverRandom,
        PrfHash hash = PrfHash.Sha256)
    {
        Span<byte> seed = stackalloc byte[clientRandom.Length + serverRandom.Length];
        clientRandom.CopyTo(seed);
        serverRandom.CopyTo(seed[clientRandom.Length..]);
        return Prf(preMasterSecret, MasterSecretLabel, seed, MasterSecretLength, hash);
    }

    /// <summary>Extended master secret derivation over the session hash (RFC 7627 §4).</summary>
    public static byte[] ExtendedMasterSecret(
        ReadOnlySpan<byte> preMasterSecret,
        ReadOnlySpan<byte> sessionHash,
        PrfHash hash = PrfHash.Sha256) =>
        Prf(preMasterSecret, ExtendedMasterSecretLabel, sessionHash, MasterSecretLength, hash);

    /// <summary>
    /// Key block expansion (RFC 5246 §6.3). Note the seed order is <c>server_random || client_random</c>,
    /// the reverse of the master secret seed.
    /// </summary>
    public static byte[] KeyBlock(
        ReadOnlySpan<byte> masterSecret,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom,
        int length,
        PrfHash hash = PrfHash.Sha256)
    {
        Span<byte> seed = stackalloc byte[serverRandom.Length + clientRandom.Length];
        serverRandom.CopyTo(seed);
        clientRandom.CopyTo(seed[serverRandom.Length..]);
        return Prf(masterSecret, KeyExpansionLabel, seed, length, hash);
    }

    /// <summary>Finished <c>verify_data</c> (RFC 5246 §7.4.9).</summary>
    public static byte[] VerifyData(
        ReadOnlySpan<byte> masterSecret,
        string label,
        ReadOnlySpan<byte> transcriptHash,
        PrfHash hash = PrfHash.Sha256) =>
        Prf(masterSecret, label, transcriptHash, DtlsLimits.VerifyDataLength, hash);

    /// <summary>
    /// RFC 5705 keying material exporter with no context value, as required by DTLS-SRTP
    /// (RFC 5764 §4.2). The seed is <c>client_random || server_random</c>.
    /// </summary>
    public static byte[] ExportKeyingMaterial(
        ReadOnlySpan<byte> masterSecret,
        string label,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom,
        int length,
        PrfHash hash = PrfHash.Sha256)
    {
        Span<byte> seed = stackalloc byte[clientRandom.Length + serverRandom.Length];
        clientRandom.CopyTo(seed);
        serverRandom.CopyTo(seed[clientRandom.Length..]);
        return Prf(masterSecret, label, seed, length, hash);
    }

    private static int HashLength(PrfHash hash) => hash == PrfHash.Sha384 ? Sha384Length : Sha256Length;

    private static void HmacHashData(PrfHash hash, ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        _ = hash == PrfHash.Sha384
            ? HMACSHA384.HashData(key, source, destination)
            : HMACSHA256.HashData(key, source, destination);
    }
}
