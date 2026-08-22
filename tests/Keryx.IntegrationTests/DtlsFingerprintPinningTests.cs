using FluentAssertions;
using Keryx;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// The SDP <c>a=fingerprint</c> attribute is the entire trust anchor of the WebRTC security model
/// (RFC 8827 §6.5): the peer's DTLS certificate is self-signed, so nothing about the certificate
/// itself carries trust. These tests drive a real <see cref="PeerConnection"/> with signalling an
/// attacker has tampered with and assert it refuses to connect.
/// </summary>
public sealed class DtlsFingerprintPinningTests
{
    /// <summary>
    /// Strip every <c>a=fingerprint</c> line from the offer, as an attacker sitting on the
    /// signalling channel would. Without a fingerprint the DTLS handshake would pin nothing and
    /// accept any certificate, so the connection must fail instead.
    /// </summary>
    [Fact]
    public async Task An_offer_with_no_fingerprint_is_refused()
    {
        var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(40)).Token;

        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        var offer = await offerer.CreateOfferAsync(cancellationToken);
        var stripped = StripLines(offer, "a=fingerprint:");
        stripped.Should().NotContain("a=fingerprint:", "the attacker removed the trust anchor");

        // Complete the exchange so ICE really connects: without the fix the DTLS handshake runs to
        // completion against an unpinned certificate and the answerer reaches Connected, which is
        // precisely the unauthenticated session this test exists to prevent.
        await answerer.SetRemoteDescriptionAsync(stripped, SdpType.Offer, cancellationToken);
        var answer = await answerer.CreateAnswerAsync(cancellationToken);
        await offerer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        var failed = await TestSupport.WaitForAsync(
            () => answerer.State == PeerConnectionState.Failed,
            25_000);

        failed.Should().BeTrue(
            "a remote description with no a=fingerprint must fail closed, not connect unauthenticated");
        answerer.State.Should().NotBe(PeerConnectionState.Connected);
    }

    /// <summary>
    /// Keryx computes SHA-256 fingerprints only. An offer pinning a SHA-1 digest must be refused
    /// explicitly rather than silently compared against a SHA-256 digest and reported as a mismatch.
    /// </summary>
    [Fact]
    public async Task An_offer_pinning_a_non_sha256_fingerprint_is_refused()
    {
        var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(40)).Token;

        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        var offer = await offerer.CreateOfferAsync(cancellationToken);
        var downgraded = string.Join(
            "\r\n",
            offer.ReplaceLineEndings("\n").Split('\n')
                .Select(line => line.StartsWith("a=fingerprint:", StringComparison.Ordinal)
                    ? "a=fingerprint:sha-1 " + string.Join(':', Enumerable.Repeat("AA", 20))
                    : line));

        await answerer.SetRemoteDescriptionAsync(downgraded, SdpType.Offer, cancellationToken);
        var answer = await answerer.CreateAnswerAsync(cancellationToken);
        await offerer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        var failed = await TestSupport.WaitForAsync(
            () => answerer.State == PeerConnectionState.Failed,
            25_000);

        failed.Should().BeTrue("Keryx only pins sha-256 digests, so any other algorithm must fail closed");
        answerer.State.Should().NotBe(PeerConnectionState.Connected);
    }

    /// <summary>
    /// The positive control: an offer whose fingerprint has been swapped for a syntactically valid
    /// but wrong SHA-256 digest must also fail — this is the tampered-fingerprint case, and it
    /// proves the pin is actually consulted rather than merely present.
    /// </summary>
    [Fact]
    public async Task An_offer_pinning_the_wrong_sha256_fingerprint_is_refused()
    {
        var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(40)).Token;

        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        var offer = await offerer.CreateOfferAsync(cancellationToken);
        var tampered = string.Join(
            "\r\n",
            offer.ReplaceLineEndings("\n").Split('\n')
                .Select(line => line.StartsWith("a=fingerprint:", StringComparison.Ordinal)
                    ? "a=fingerprint:sha-256 " + string.Join(':', Enumerable.Repeat("AA", 32))
                    : line));

        await answerer.SetRemoteDescriptionAsync(tampered, SdpType.Offer, cancellationToken);
        var answer = await answerer.CreateAnswerAsync(cancellationToken);
        await offerer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        var failed = await TestSupport.WaitForAsync(
            () => answerer.State == PeerConnectionState.Failed,
            25_000);

        failed.Should().BeTrue("a fingerprint that does not match the peer's certificate must abort the handshake");
        answerer.State.Should().NotBe(PeerConnectionState.Connected);
    }

    private static string StripLines(string sdp, string prefix) => string.Join(
        "\r\n",
        sdp.ReplaceLineEndings("\n").Split('\n')
            .Where(line => !line.StartsWith(prefix, StringComparison.Ordinal)));
}
