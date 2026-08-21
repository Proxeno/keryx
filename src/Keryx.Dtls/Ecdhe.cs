using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Keryx.Dtls;

/// <summary>
/// ECDHE key agreement and the signature helpers used by ServerKeyExchange and CertificateVerify.
/// </summary>
/// <remarks>
/// Every primitive here is a BCL call; only the TLS-specific encodings (uncompressed point format,
/// <c>SignatureAndHashAlgorithm</c> dispatch) are Keryx's own.
/// </remarks>
internal static class Ecdhe
{
    /// <summary>Coordinate size of secp256r1 in bytes.</summary>
    public const int P256CoordinateLength = 32;

    /// <summary>Length of an uncompressed secp256r1 point: <c>0x04 || X || Y</c>.</summary>
    public const int P256PointLength = 1 + (2 * P256CoordinateLength);

    public static ECDiffieHellman CreateP256() => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

    /// <summary>Exports the local public key in the TLS uncompressed point format (RFC 8422 §5.4.1).</summary>
    public static byte[] ExportPoint(ECDiffieHellman ecdh)
    {
        var parameters = ecdh.ExportParameters(false);
        var point = new byte[P256PointLength];
        point[0] = 0x04;
        CopyRightAligned(parameters.Q.X!, point.AsSpan(1, P256CoordinateLength));
        CopyRightAligned(parameters.Q.Y!, point.AsSpan(1 + P256CoordinateLength, P256CoordinateLength));
        return point;
    }

    /// <summary>
    /// Derives the TLS pre-master secret: the X coordinate of the shared point, unhashed
    /// (RFC 8422 §5.10). Rejects malformed or off-curve peer points.
    /// </summary>
    public static byte[] DerivePreMasterSecret(ECDiffieHellman local, ReadOnlySpan<byte> peerPoint)
    {
        if (peerPoint.Length != P256PointLength || peerPoint[0] != 0x04)
        {
            throw new DtlsException(
                "Peer ECDHE point is not a valid uncompressed secp256r1 point.",
                DtlsAlertDescription.IllegalParameter);
        }

        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = peerPoint.Slice(1, P256CoordinateLength).ToArray(),
                Y = peerPoint.Slice(1 + P256CoordinateLength, P256CoordinateLength).ToArray(),
            },
        };

        try
        {
            // Validate() rejects points that are not on the curve, which is the check that stops
            // invalid-curve attacks against the static half of the exchange.
            parameters.Validate();
            using var peer = ECDiffieHellman.Create(parameters);
            return local.DeriveRawSecretAgreement(peer.PublicKey);
        }
        catch (CryptographicException ex)
        {
            throw new DtlsException("Peer ECDHE point was rejected.", DtlsAlertDescription.IllegalParameter, ex);
        }
    }

    /// <summary>Signs <paramref name="data"/> with the local certificate key using <paramref name="algorithm"/>.</summary>
    public static byte[] Sign(DtlsCertificate certificate, SigHashAlgorithm algorithm, ReadOnlySpan<byte> data)
    {
        var hashName = HashName(algorithm.Hash);
        if (algorithm.Signature == SignatureAlgorithms.Ecdsa)
        {
            var key = certificate.EcdsaKey
                      ?? throw new DtlsException(
                          "An ECDSA signature was negotiated but the local certificate has no ECDSA key.",
                          DtlsAlertDescription.InternalError);
            return key.SignData(data, hashName, DSASignatureFormat.Rfc3279DerSequence);
        }

        if (algorithm.Signature == SignatureAlgorithms.Rsa)
        {
            var key = certificate.RsaKey
                      ?? throw new DtlsException(
                          "An RSA signature was negotiated but the local certificate has no RSA key.",
                          DtlsAlertDescription.InternalError);
            return key.SignData(data, hashName, RSASignaturePadding.Pkcs1);
        }

        throw new DtlsException(
            $"Unsupported signature algorithm {algorithm}.",
            DtlsAlertDescription.HandshakeFailure);
    }

    /// <summary>Verifies a peer signature against the public key in <paramref name="certificate"/>.</summary>
    public static bool Verify(
        X509Certificate2 certificate,
        SigHashAlgorithm algorithm,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
    {
        HashAlgorithmName hashName;
        try
        {
            hashName = HashName(algorithm.Hash);
        }
        catch (DtlsException)
        {
            return false;
        }

        try
        {
            if (algorithm.Signature == SignatureAlgorithms.Ecdsa)
            {
                using var key = certificate.GetECDsaPublicKey();
                return key is not null
                       && key.VerifyData(data, signature, hashName, DSASignatureFormat.Rfc3279DerSequence);
            }

            if (algorithm.Signature == SignatureAlgorithms.Rsa)
            {
                using var key = certificate.GetRSAPublicKey();
                return key is not null && key.VerifyData(data, signature, hashName, RSASignaturePadding.Pkcs1);
            }
        }
        catch (CryptographicException)
        {
            return false;
        }

        return false;
    }

    private static HashAlgorithmName HashName(byte hash) => hash switch
    {
        HashAlgorithms.Sha256 => HashAlgorithmName.SHA256,
        HashAlgorithms.Sha384 => HashAlgorithmName.SHA384,
        HashAlgorithms.Sha512 => HashAlgorithmName.SHA512,
        _ => throw new DtlsException(
            $"Unsupported TLS hash algorithm {hash}.",
            DtlsAlertDescription.HandshakeFailure),
    };

    private static void CopyRightAligned(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        if (source.Length > destination.Length)
        {
            source[^destination.Length..].CopyTo(destination);
            return;
        }

        destination.Clear();
        source.CopyTo(destination[(destination.Length - source.Length)..]);
    }
}
