using System.Numerics;
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
    private static readonly BigInteger P256Prime = BigInteger.Parse(
        "0FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
        System.Globalization.NumberStyles.HexNumber,
        System.Globalization.CultureInfo.InvariantCulture);

    private static readonly BigInteger P256B = BigInteger.Parse(
        "05AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
        System.Globalization.NumberStyles.HexNumber,
        System.Globalization.CultureInfo.InvariantCulture);

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

        // ECParameters.Validate() is a *structural* check — it confirms the coordinates are present
        // and the right width for the curve, and does no curve arithmetic at all. Because the slicing
        // above already guarantees two 32-byte coordinates, it can never fail here. The on-curve check
        // that actually stops invalid-curve attacks therefore has to be done explicitly rather than
        // left to the key-import path of whichever platform provider happens to be in use.
        if (!IsOnP256Curve(parameters.Q.X!, parameters.Q.Y!))
        {
            throw new DtlsException(
                "Peer ECDHE point is not on the secp256r1 curve.",
                DtlsAlertDescription.IllegalParameter);
        }

        try
        {
            using var peer = ECDiffieHellman.Create(parameters);
            return local.DeriveRawSecretAgreement(peer.PublicKey);
        }
        catch (CryptographicException ex)
        {
            throw new DtlsException("Peer ECDHE point was rejected.", DtlsAlertDescription.IllegalParameter, ex);
        }
    }

    /// <summary>
    /// True when <c>(x, y)</c> satisfies the secp256r1 curve equation <c>y² = x³ - 3x + b (mod p)</c>
    /// and both coordinates are reduced modulo <c>p</c>.
    /// </summary>
    /// <remarks>
    /// Feeding an off-curve point into a raw ECDH agreement is the invalid-curve attack: the peer
    /// picks a point on a different curve with a small-order subgroup, and each handshake leaks the
    /// local scalar modulo that small order until the whole key can be reassembled by CRT. Keryx uses
    /// an ephemeral key per handshake, which is what keeps this from being catastrophic today, but the
    /// check must not depend on that — a future change that cached the key would silently turn this
    /// into key recovery. The point at infinity is encoded as <c>(0, 0)</c> here and is rejected with
    /// everything else off the curve.
    /// </remarks>
    private static bool IsOnP256Curve(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y)
    {
        var xv = new BigInteger(x, isUnsigned: true, isBigEndian: true);
        var yv = new BigInteger(y, isUnsigned: true, isBigEndian: true);
        if (xv >= P256Prime || yv >= P256Prime)
        {
            return false;
        }

        if (xv.IsZero && yv.IsZero)
        {
            return false;
        }

        var left = BigInteger.Remainder(yv * yv, P256Prime);
        var right = BigInteger.Remainder((xv * xv * xv) - (3 * xv) + P256B, P256Prime);
        if (right.Sign < 0)
        {
            right += P256Prime;
        }

        return left == right;
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
