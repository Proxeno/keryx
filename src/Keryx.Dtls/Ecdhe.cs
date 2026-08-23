using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Keryx.Dtls;

/// <summary>
/// ECDHE key agreement and the signature helpers used by ServerKeyExchange and CertificateVerify.
/// </summary>
/// <remarks>
/// Every primitive here is a BCL call; only the TLS-specific encodings (uncompressed point format,
/// <c>SignatureAndHashAlgorithm</c> dispatch) are Keryx's own. Two NIST curves are supported —
/// secp256r1 (P-256) and secp384r1 (P-384) — both exposed by <see cref="ECDiffieHellman"/>. x25519 is
/// not, because the .NET 10 BCL has no X25519 key agreement.
/// </remarks>
internal static class Ecdhe
{
    /// <summary>Coordinate size of secp256r1 in bytes.</summary>
    public const int P256CoordinateLength = 32;

    /// <summary>Length of an uncompressed secp256r1 point: <c>0x04 || X || Y</c>.</summary>
    public const int P256PointLength = 1 + (2 * P256CoordinateLength);

    // secp256r1 domain parameters used by the explicit on-curve check.
    private static readonly BigInteger P256Prime = BigInteger.Parse(
        "0FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
        System.Globalization.NumberStyles.HexNumber,
        System.Globalization.CultureInfo.InvariantCulture);

    private static readonly BigInteger P256B = BigInteger.Parse(
        "05AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
        System.Globalization.NumberStyles.HexNumber,
        System.Globalization.CultureInfo.InvariantCulture);

    // secp384r1 domain parameters. The prime is 2^384 - 2^128 - 2^96 + 2^32 - 1, built here rather
    // than transcribed as hex; b is the curve constant from FIPS 186-4 / SEC 2, parsed with a leading
    // zero nibble so it is read as a positive value.
    private static readonly BigInteger P384Prime =
        (BigInteger.One << 384) - (BigInteger.One << 128) - (BigInteger.One << 96) + (BigInteger.One << 32) - 1;

    private static readonly BigInteger P384B = BigInteger.Parse(
        "0B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875A" +
        "C656398D8A2ED19D2A85C8EDD3EC2AEF",
        System.Globalization.NumberStyles.HexNumber,
        System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>secp256r1 domain parameters, the WebRTC default curve.</summary>
    public static ECDiffieHellman CreateP256() => Create(NamedGroups.Secp256r1);

    /// <summary>Creates an ephemeral ECDHE key for the given TLS named group.</summary>
    public static ECDiffieHellman Create(ushort namedGroup) => ECDiffieHellman.Create(CurveOf(namedGroup));

    /// <summary>Coordinate size, in bytes, of the given named group.</summary>
    public static int CoordinateLength(ushort namedGroup) => namedGroup switch
    {
        NamedGroups.Secp256r1 => 32,
        NamedGroups.Secp384r1 => 48,
        _ => throw UnsupportedGroup(namedGroup),
    };

    /// <summary>Length of an uncompressed point (<c>0x04 || X || Y</c>) for the given named group.</summary>
    public static int PointLength(ushort namedGroup) => 1 + (2 * CoordinateLength(namedGroup));

    /// <summary>Exports the local public key in the TLS uncompressed point format (RFC 8422 §5.4.1).</summary>
    public static byte[] ExportPoint(ECDiffieHellman ecdh) => ExportPoint(ecdh, NamedGroups.Secp256r1);

    /// <summary>Exports the local public key in the TLS uncompressed point format for the given group.</summary>
    public static byte[] ExportPoint(ECDiffieHellman ecdh, ushort namedGroup)
    {
        var coordinate = CoordinateLength(namedGroup);
        var parameters = ecdh.ExportParameters(false);
        var point = new byte[1 + (2 * coordinate)];
        point[0] = 0x04;
        CopyRightAligned(parameters.Q.X!, point.AsSpan(1, coordinate));
        CopyRightAligned(parameters.Q.Y!, point.AsSpan(1 + coordinate, coordinate));
        return point;
    }

    /// <summary>
    /// Derives the TLS pre-master secret over secp256r1: the X coordinate of the shared point,
    /// unhashed (RFC 8422 §5.10). Rejects malformed or off-curve peer points.
    /// </summary>
    public static byte[] DerivePreMasterSecret(ECDiffieHellman local, ReadOnlySpan<byte> peerPoint) =>
        DerivePreMasterSecret(local, peerPoint, NamedGroups.Secp256r1);

    /// <summary>
    /// Derives the TLS pre-master secret over the given named group: the X coordinate of the shared
    /// point, unhashed (RFC 8422 §5.10). Rejects malformed or off-curve peer points.
    /// </summary>
    public static byte[] DerivePreMasterSecret(ECDiffieHellman local, ReadOnlySpan<byte> peerPoint, ushort namedGroup)
    {
        var coordinate = CoordinateLength(namedGroup);
        var pointLength = 1 + (2 * coordinate);
        if (peerPoint.Length != pointLength || peerPoint[0] != 0x04)
        {
            throw new DtlsException(
                "Peer ECDHE point is not a valid uncompressed point for the negotiated curve.",
                DtlsAlertDescription.IllegalParameter);
        }

        var parameters = new ECParameters
        {
            Curve = CurveOf(namedGroup),
            Q = new ECPoint
            {
                X = peerPoint.Slice(1, coordinate).ToArray(),
                Y = peerPoint.Slice(1 + coordinate, coordinate).ToArray(),
            },
        };

        // ECParameters.Validate() is a *structural* check — it confirms the coordinates are present
        // and the right width for the curve, and does no curve arithmetic at all. Because the slicing
        // above already guarantees two coordinates of the right width, it can never fail here. The
        // on-curve check that actually stops invalid-curve attacks therefore has to be done explicitly
        // rather than left to the key-import path of whichever platform provider happens to be in use.
        if (!IsOnCurve(namedGroup, parameters.Q.X!, parameters.Q.Y!))
        {
            throw new DtlsException(
                "Peer ECDHE point is not on the negotiated curve.",
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

    /// <summary>
    /// True when <c>(x, y)</c> satisfies the curve equation <c>y² = x³ - 3x + b (mod p)</c> for the
    /// given group and both coordinates are reduced modulo <c>p</c>.
    /// </summary>
    /// <remarks>
    /// Feeding an off-curve point into a raw ECDH agreement is the invalid-curve attack: the peer
    /// picks a point on a different curve with a small-order subgroup, and each handshake leaks the
    /// local scalar modulo that small order until the whole key can be reassembled by CRT. Keryx uses
    /// an ephemeral key per handshake, which is what keeps this from being catastrophic today, but the
    /// check must not depend on that — a future change that cached the key would silently turn this
    /// into key recovery. The point at infinity is encoded as <c>(0, 0)</c> here and is rejected with
    /// everything else off the curve. Both supported NIST curves use <c>a = -3</c>.
    /// </remarks>
    private static bool IsOnCurve(ushort namedGroup, ReadOnlySpan<byte> x, ReadOnlySpan<byte> y)
    {
        var (prime, b) = namedGroup switch
        {
            NamedGroups.Secp256r1 => (P256Prime, P256B),
            NamedGroups.Secp384r1 => (P384Prime, P384B),
            _ => throw UnsupportedGroup(namedGroup),
        };

        var xv = new BigInteger(x, isUnsigned: true, isBigEndian: true);
        var yv = new BigInteger(y, isUnsigned: true, isBigEndian: true);
        if (xv >= prime || yv >= prime)
        {
            return false;
        }

        if (xv.IsZero && yv.IsZero)
        {
            return false;
        }

        var left = BigInteger.Remainder(yv * yv, prime);
        var right = BigInteger.Remainder((xv * xv * xv) - (3 * xv) + b, prime);
        if (right.Sign < 0)
        {
            right += prime;
        }

        return left == right;
    }

    private static ECCurve CurveOf(ushort namedGroup) => namedGroup switch
    {
        NamedGroups.Secp256r1 => ECCurve.NamedCurves.nistP256,
        NamedGroups.Secp384r1 => ECCurve.NamedCurves.nistP384,
        _ => throw UnsupportedGroup(namedGroup),
    };

    private static DtlsException UnsupportedGroup(ushort namedGroup) => new(
        $"Unsupported ECDHE named group 0x{namedGroup:X4}.",
        DtlsAlertDescription.HandshakeFailure);

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
