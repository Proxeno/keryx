using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace Keryx.Dtls.Tests;

public class DtlsCertificateTests
{
    [Fact]
    public void Generated_certificate_is_self_signed_ecdsa_p256()
    {
        using var certificate = DtlsCertificate.GenerateSelfSigned();

        certificate.IsEcdsa.Should().BeTrue();
        certificate.Certificate.Subject.Should().Be("CN=keryx");
        certificate.Certificate.Issuer.Should().Be(certificate.Certificate.Subject);
        certificate.Certificate.NotAfter.Should().BeAfter(DateTime.Now);
        certificate.Certificate.NotBefore.Should().BeBefore(DateTime.Now);

        using var publicKey = certificate.Certificate.GetECDsaPublicKey();
        publicKey.Should().NotBeNull();
        publicKey!.KeySize.Should().Be(256);
    }

    [Fact]
    public void Generated_certificate_can_sign_and_the_public_key_verifies()
    {
        using var certificate = DtlsCertificate.GenerateSelfSigned();
        var data = "handshake transcript"u8.ToArray();

        var signature = Ecdhe.Sign(certificate, SigHashAlgorithm.EcdsaSha256, data);

        Ecdhe.Verify(certificate.Certificate, SigHashAlgorithm.EcdsaSha256, data, signature).Should().BeTrue();
        data[0] ^= 0xFF;
        Ecdhe.Verify(certificate.Certificate, SigHashAlgorithm.EcdsaSha256, data, signature).Should().BeFalse();
    }

    [Fact]
    public void Fingerprint_is_uppercase_colon_separated_sha256_of_the_der()
    {
        using var certificate = DtlsCertificate.GenerateSelfSigned();

        certificate.Sha256Fingerprint.Should().MatchRegex("^[0-9A-F]{2}(:[0-9A-F]{2}){31}$");
        certificate.Sha256Fingerprint.Should()
            .Be(DtlsCertificate.FormatFingerprint(SHA256.HashData(certificate.DerEncoded)));
        Regex.Replace(certificate.Sha256Fingerprint, ":", string.Empty).Should()
            .Be(Convert.ToHexString(SHA256.HashData(certificate.Certificate.RawData)));
    }

    [Fact]
    public void Two_generated_certificates_have_different_fingerprints()
    {
        using var a = DtlsCertificate.GenerateSelfSigned();
        using var b = DtlsCertificate.GenerateSelfSigned();

        a.Sha256Fingerprint.Should().NotBe(b.Sha256Fingerprint);
    }

    [Fact]
    public void Validity_window_defaults_to_about_thirty_days()
    {
        using var certificate = DtlsCertificate.GenerateSelfSigned();

        var lifetime = certificate.Certificate.NotAfter - certificate.Certificate.NotBefore;
        lifetime.Should().BeCloseTo(TimeSpan.FromDays(30), TimeSpan.FromMinutes(1));
    }

    [Fact]
    public void Custom_validity_is_honoured()
    {
        using var certificate = DtlsCertificate.GenerateSelfSigned("shortlived", TimeSpan.FromHours(2));

        certificate.Certificate.Subject.Should().Be("CN=shortlived");
        (certificate.Certificate.NotAfter - certificate.Certificate.NotBefore)
            .Should().BeCloseTo(TimeSpan.FromHours(2), TimeSpan.FromMinutes(1));
    }

    [Theory]
    [InlineData("AB:CD", "ab:cd", true)]
    [InlineData("AB:CD", "ABCD", true)]
    [InlineData("AB:CD", " ab-cd ", true)]
    [InlineData("AB:CD", "AB:CE", false)]
    [InlineData("AB:CD", "", false)]
    [InlineData("", "AB:CD", false)]
    [InlineData(null, "AB:CD", false)]
    public void Fingerprint_comparison_ignores_case_and_separators(string? left, string? right, bool expected)
    {
        DtlsCertificate.FingerprintsEqual(left, right).Should().Be(expected);
    }

    [Fact]
    public void FromCertificate_rejects_a_certificate_without_a_private_key()
    {
        using var source = DtlsCertificate.GenerateSelfSigned();
        using var publicOnly = X509CertificateLoader.LoadCertificate(source.DerEncoded);

        var act = () => DtlsCertificate.FromCertificate(publicOnly);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void FromCertificate_wraps_an_ecdsa_certificate()
    {
        using var source = DtlsCertificate.GenerateSelfSigned();

        using var wrapped = DtlsCertificate.FromCertificate(source.Certificate);

        wrapped.IsEcdsa.Should().BeTrue();
        wrapped.Sha256Fingerprint.Should().Be(source.Sha256Fingerprint);
    }

    [Fact]
    public void ComputeSha256Fingerprint_matches_the_instance_property()
    {
        using var certificate = DtlsCertificate.GenerateSelfSigned();

        DtlsCertificate.ComputeSha256Fingerprint(certificate.DerEncoded)
            .Should().Be(certificate.Sha256Fingerprint);
    }
}
