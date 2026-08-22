using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Keryx.Dtls;

/// <summary>
/// The local end-entity certificate and its private key, plus the SHA-256 fingerprint that goes
/// into the SDP <c>a=fingerprint</c> attribute.
/// </summary>
/// <remarks>
/// WebRTC does not use a PKI: both peers present self-signed certificates and authenticate each
/// other by comparing the certificate's SHA-256 fingerprint against the one carried in the signed
/// signalling exchange. <see cref="GenerateSelfSigned"/> produces exactly the kind of certificate
/// browsers generate — a short-lived ECDSA P-256 self-signed leaf.
/// </remarks>
public sealed class DtlsCertificate : IDisposable
{
    private readonly ECDsa? _ecdsa;
    private readonly RSA? _rsa;
    private readonly bool _ownsKeys;
    private bool _disposed;

    private DtlsCertificate(X509Certificate2 certificate, ECDsa? ecdsa, RSA? rsa, bool ownsKeys)
    {
        Certificate = certificate;
        _ecdsa = ecdsa;
        _rsa = rsa;
        _ownsKeys = ownsKeys;
        DerEncoded = certificate.RawDataMemory.ToArray();
        Sha256Fingerprint = FormatFingerprint(SHA256.HashData(DerEncoded));
    }

    /// <summary>The X.509 certificate presented to the peer.</summary>
    public X509Certificate2 Certificate { get; }

    /// <summary>The DER encoding of <see cref="Certificate"/>, as sent in the TLS Certificate message.</summary>
    public byte[] DerEncoded { get; }

    /// <summary>
    /// Uppercase, colon-separated SHA-256 hash of the DER certificate — the exact form used by
    /// <c>a=fingerprint:sha-256 …</c> in SDP (RFC 8122).
    /// </summary>
    public string Sha256Fingerprint { get; }

    /// <summary>True when the private key is ECDSA (the WebRTC default), false when it is RSA.</summary>
    public bool IsEcdsa => _ecdsa is not null;

    internal ECDsa? EcdsaKey => _ecdsa;

    internal RSA? RsaKey => _rsa;

    /// <summary>
    /// Generates a fresh self-signed ECDSA P-256 certificate, the WebRTC-standard identity.
    /// </summary>
    /// <param name="commonName">Subject/issuer common name. Defaults to <c>keryx</c>.</param>
    /// <param name="validity">Lifetime of the certificate. Defaults to 30 days.</param>
    /// <returns>A new certificate that owns its private key and must be disposed.</returns>
    public static DtlsCertificate GenerateSelfSigned(string commonName = "keryx", TimeSpan? validity = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(commonName);

        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        try
        {
            var request = new CertificateRequest($"CN={commonName}", key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));

            // Back-date slightly so a peer with a modestly skewed clock still sees a valid window.
            var notBefore = DateTimeOffset.UtcNow.AddMinutes(-15);
            var notAfter = notBefore + (validity ?? TimeSpan.FromDays(30));
            var certificate = request.CreateSelfSigned(notBefore, notAfter);
            return new DtlsCertificate(certificate, key, null, ownsKeys: true);
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Wraps an existing certificate. The certificate must carry a usable ECDSA or RSA private key;
    /// the returned instance does not take ownership of <paramref name="certificate"/> itself but
    /// does own the private key handle it extracts.
    /// </summary>
    /// <param name="certificate">A certificate with an accessible private key.</param>
    /// <returns>A wrapper suitable for <see cref="DtlsConfig.Certificate"/>.</returns>
    /// <exception cref="ArgumentException">The certificate has no supported private key.</exception>
    public static DtlsCertificate FromCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        var ecdsa = certificate.GetECDsaPrivateKey();
        if (ecdsa is not null)
        {
            return new DtlsCertificate(certificate, ecdsa, null, ownsKeys: true);
        }

        var rsa = certificate.GetRSAPrivateKey();
        if (rsa is not null)
        {
            return new DtlsCertificate(certificate, null, rsa, ownsKeys: true);
        }

        throw new ArgumentException(
            "The certificate must have an accessible ECDSA or RSA private key.",
            nameof(certificate));
    }

    /// <summary>
    /// Formats a hash as uppercase colon-separated hex, e.g. <c>AB:CD:EF:…</c>.
    /// </summary>
    /// <param name="hash">The raw hash bytes.</param>
    /// <returns>The SDP fingerprint representation.</returns>
    public static string FormatFingerprint(ReadOnlySpan<byte> hash)
    {
        if (hash.Length == 0)
        {
            return string.Empty;
        }

        return string.Create(
            (hash.Length * 3) - 1,
            hash.ToArray(),
            static (span, bytes) =>
            {
                const string Hex = "0123456789ABCDEF";
                var index = 0;
                for (var i = 0; i < bytes.Length; i++)
                {
                    if (i > 0)
                    {
                        span[index++] = ':';
                    }

                    span[index++] = Hex[bytes[i] >> 4];
                    span[index++] = Hex[bytes[i] & 0x0F];
                }
            });
    }

    /// <summary>Computes the SDP-style SHA-256 fingerprint of a DER-encoded certificate.</summary>
    /// <param name="derEncodedCertificate">The DER bytes of the certificate.</param>
    /// <returns>Uppercase colon-separated hex.</returns>
    public static string ComputeSha256Fingerprint(ReadOnlySpan<byte> derEncodedCertificate) =>
        FormatFingerprint(SHA256.HashData(derEncodedCertificate));

    /// <summary>
    /// Compares two fingerprints ignoring case, separators and surrounding whitespace, so a value
    /// copied verbatim out of SDP compares equal to <see cref="Sha256Fingerprint"/>.
    /// </summary>
    /// <param name="left">First fingerprint.</param>
    /// <param name="right">Second fingerprint.</param>
    /// <returns>True when both denote the same hash.</returns>
    public static bool FingerprintsEqual(string? left, string? right)
    {
        var a = Normalize(left);
        var b = Normalize(right);
        if (a.Length == 0 || b.Length == 0)
        {
            return false;
        }

        return string.Equals(a, b, StringComparison.Ordinal);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_ownsKeys)
        {
            _ecdsa?.Dispose();
            _rsa?.Dispose();
        }

        Certificate.Dispose();
    }

    private static string Normalize(string? fingerprint)
    {
        if (string.IsNullOrWhiteSpace(fingerprint))
        {
            return string.Empty;
        }

        Span<char> buffer = fingerprint.Length <= 256 ? stackalloc char[fingerprint.Length] : new char[fingerprint.Length];
        var length = 0;
        foreach (var c in fingerprint)
        {
            if (c is ':' or '-' or ' ' or '\t')
            {
                continue;
            }

            buffer[length++] = char.ToUpperInvariant(c);
        }

        return new string(buffer[..length]);
    }
}
