using System.Security.Cryptography;
using FluentAssertions;
using Xunit;

namespace Keryx.Dtls.Tests;

/// <summary>
/// The ECDHE half of the handshake. Two properties here are silent when wrong — a peer point that is
/// not on the curve, and a pre-master secret that has been run through a KDF — because both leave the
/// implementation perfectly interoperable with itself while being wrong against the RFC or unsafe.
/// </summary>
public class EcdheTests
{
    private static byte[] ValidPoint(out ECDiffieHellman key)
    {
        key = Ecdhe.CreateP256();
        return Ecdhe.ExportPoint(key);
    }

    /// <summary>
    /// The invalid-curve attack (RFC 8422 §5.4.1 requires the point to be validated): a peer offers a
    /// point on a different curve with a small-order subgroup, and each agreement leaks the local
    /// scalar modulo that order. <c>ECParameters.Validate()</c> is only a structural check and does
    /// no curve arithmetic, so this must be caught by an explicit on-curve test.
    /// </summary>
    [Fact]
    public void A_point_off_the_curve_is_rejected()
    {
        using var local = Ecdhe.CreateP256();
        var point = ValidPoint(out var peer);
        using (peer)
        {
            // Flip the low bit of Y. The result is overwhelmingly unlikely to satisfy
            // y^2 = x^3 - 3x + b, so it is not a point on secp256r1.
            point[^1] ^= 0x01;

            var derive = () => Ecdhe.DerivePreMasterSecret(local, point);
            derive.Should().Throw<DtlsException>()
                .Which.Alert.Should().Be(DtlsAlertDescription.IllegalParameter);
        }
    }

    /// <summary>The point at infinity, encoded here as (0, 0), has no place in an ECDHE exchange.</summary>
    [Fact]
    public void The_point_at_infinity_is_rejected()
    {
        using var local = Ecdhe.CreateP256();
        var point = new byte[65];
        point[0] = 0x04;

        var derive = () => Ecdhe.DerivePreMasterSecret(local, point);
        derive.Should().Throw<DtlsException>()
            .Which.Alert.Should().Be(DtlsAlertDescription.IllegalParameter);
    }

    /// <summary>A coordinate at or above the field prime is not a canonical encoding.</summary>
    [Fact]
    public void A_coordinate_not_reduced_modulo_the_field_prime_is_rejected()
    {
        using var local = Ecdhe.CreateP256();
        var point = new byte[65];
        point[0] = 0x04;
        point.AsSpan(1, 32).Fill(0xFF); // X = 2^256 - 1, far above p.

        var derive = () => Ecdhe.DerivePreMasterSecret(local, point);
        derive.Should().Throw<DtlsException>()
            .Which.Alert.Should().Be(DtlsAlertDescription.IllegalParameter);
    }

    /// <summary>RFC 8422 §5.4.1: only the uncompressed form is defined for TLS ECDHE.</summary>
    [Theory]
    [InlineData((byte)0x00)]
    [InlineData((byte)0x02)]
    [InlineData((byte)0x03)]
    [InlineData((byte)0x06)]
    public void A_point_that_is_not_uncompressed_is_rejected(byte prefix)
    {
        using var local = Ecdhe.CreateP256();
        var point = ValidPoint(out var peer);
        using (peer)
        {
            point[0] = prefix;

            var derive = () => Ecdhe.DerivePreMasterSecret(local, point);
            derive.Should().Throw<DtlsException>()
                .Which.Alert.Should().Be(DtlsAlertDescription.IllegalParameter);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(64)]
    [InlineData(66)]
    [InlineData(33)]
    public void A_point_of_the_wrong_length_is_rejected(int length)
    {
        using var local = Ecdhe.CreateP256();
        var point = new byte[length];
        if (length > 0)
        {
            point[0] = 0x04;
        }

        var derive = () => Ecdhe.DerivePreMasterSecret(local, point);
        derive.Should().Throw<DtlsException>()
            .Which.Alert.Should().Be(DtlsAlertDescription.IllegalParameter);
    }

    /// <summary>A well-formed exchange still agrees, and agrees in both directions.</summary>
    [Fact]
    public void Two_valid_points_agree_on_the_same_pre_master_secret()
    {
        using var a = Ecdhe.CreateP256();
        using var b = Ecdhe.CreateP256();

        var fromA = Ecdhe.DerivePreMasterSecret(a, Ecdhe.ExportPoint(b));
        var fromB = Ecdhe.DerivePreMasterSecret(b, Ecdhe.ExportPoint(a));

        fromA.Should().Equal(fromB);
        fromA.Should().HaveCount(32, "the pre-master secret is the X coordinate at the field size");
    }

    /// <summary>
    /// RFC 8422 §5.10: the TLS pre-master secret is the <em>raw</em> X coordinate of the shared point.
    /// .NET's <c>DeriveKeyMaterial</c> applies a KDF by default, and using it would produce a stack
    /// that interoperates flawlessly with itself and with nothing else. This pins the distinction in
    /// both directions, so a regression to the KDF'd overload cannot pass.
    /// </summary>
    [Fact]
    public void The_pre_master_secret_is_the_raw_x_coordinate_and_not_a_kdf_of_it()
    {
        using var a = Ecdhe.CreateP256();
        using var b = Ecdhe.CreateP256();

        var raw = Ecdhe.DerivePreMasterSecret(a, Ecdhe.ExportPoint(b));
        var hashed = a.DeriveKeyMaterial(b.PublicKey);

        raw.Should().NotEqual(hashed, "DeriveKeyMaterial hashes the agreement; the TLS PMS must not be hashed");
        SHA256.HashData(raw).Should().Equal(hashed, "which confirms the two differ only by that hash");
    }
}
