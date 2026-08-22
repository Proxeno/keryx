using System.Text;
using FluentAssertions;
using Xunit;

namespace Keryx.Dtls.Tests;

public class TlsPrfTests
{
    /// <summary>
    /// The canonical TLS 1.2 PRF (P_SHA256) test vector. It originates from the IETF TLS working
    /// group mailing list ("TLS 1.2 Test vectors", 2 Nov 2010) and is reproduced in the test suites
    /// of Botan, wolfSSL and mbedTLS:
    /// secret = 9b be 43 6b a9 40 f0 17 b1 76 52 84 9a 71 db 35,
    /// label  = "test label",
    /// seed   = a0 ba 9f 93 6c da 31 18 27 a6 f7 96 ff d5 19 8c,
    /// 100 bytes of output.
    /// </summary>
    [Fact]
    public void Prf_matches_the_published_tls12_sha256_vector()
    {
        var secret = Convert.FromHexString("9BBE436BA940F017B17652849A71DB35");
        var seed = Convert.FromHexString("A0BA9F936CDA311827A6F796FFD5198C");
        const string Expected =
            "E3F229BA727BE17B8D122620557CD453C2AAB21D07C3D495329B52D4E61EDB5A" +
            "6B301791E90D35C9C9A46B4E14BAF9AF0FA022F7077DEF17ABFD3797C0564BAB" +
            "4FBC91666E9DEF9B97FCE34F796789BAA48082D122EE42C5A72E5A5110FFF701" +
            "87347B66";

        var actual = TlsPrf.Prf(secret, "test label", seed, 100);

        Convert.ToHexString(actual).Should().Be(Expected);
    }

    [Fact]
    public void Prf_output_is_a_prefix_stable_stream()
    {
        var secret = Convert.FromHexString("9BBE436BA940F017B17652849A71DB35");
        var seed = Convert.FromHexString("A0BA9F936CDA311827A6F796FFD5198C");

        var full = TlsPrf.Prf(secret, "test label", seed, 100);

        for (var length = 1; length <= 100; length++)
        {
            var partial = TlsPrf.Prf(secret, "test label", seed, length);
            partial.Should().Equal(full[..length], "P_SHA256 is a stream truncated to the requested length");
        }
    }

    [Fact]
    public void PHash_matches_a_hand_computed_two_block_expansion()
    {
        // A(1) = HMAC(secret, seed); output block i = HMAC(secret, A(i) || seed).
        var secret = Encoding.ASCII.GetBytes("secret");
        var seed = Encoding.ASCII.GetBytes("seed");

        var expected = new byte[64];
        var a1 = System.Security.Cryptography.HMACSHA256.HashData(secret, seed);
        var block1 = System.Security.Cryptography.HMACSHA256.HashData(secret, Concat(a1, seed));
        var a2 = System.Security.Cryptography.HMACSHA256.HashData(secret, a1);
        var block2 = System.Security.Cryptography.HMACSHA256.HashData(secret, Concat(a2, seed));
        block1.CopyTo(expected, 0);
        block2.CopyTo(expected, 32);

        var actual = new byte[64];
        TlsPrf.PHashSha256(secret, seed, actual);

        actual.Should().Equal(expected);
    }

    [Fact]
    public void Master_secret_is_48_bytes_and_depends_on_both_randoms()
    {
        var pms = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
        var clientRandom = new byte[32];
        var serverRandom = new byte[32];
        clientRandom[0] = 1;
        serverRandom[0] = 2;

        var a = TlsPrf.MasterSecret(pms, clientRandom, serverRandom);
        var b = TlsPrf.MasterSecret(pms, serverRandom, clientRandom);

        a.Should().HaveCount(48);
        a.Should().NotEqual(b, "the seed is client_random || server_random and is order sensitive");
    }

    [Fact]
    public void Key_block_seed_order_is_server_random_then_client_random()
    {
        var master = new byte[48];
        master[0] = 0x42;
        var clientRandom = new byte[32];
        var serverRandom = new byte[32];
        clientRandom[31] = 1;
        serverRandom[31] = 2;

        var keyBlock = TlsPrf.KeyBlock(master, clientRandom, serverRandom, 40);

        var seed = new byte[64];
        serverRandom.CopyTo(seed, 0);
        clientRandom.CopyTo(seed, 32);
        var expected = TlsPrf.Prf(master, "key expansion", seed, 40);

        keyBlock.Should().Equal(expected);
    }

    [Fact]
    public void Exporter_seed_order_is_client_random_then_server_random()
    {
        var master = new byte[48];
        master[7] = 0x99;
        var clientRandom = new byte[32];
        var serverRandom = new byte[32];
        clientRandom[3] = 7;
        serverRandom[9] = 8;

        var exported = TlsPrf.ExportKeyingMaterial(master, "EXTRACTOR-dtls_srtp", clientRandom, serverRandom, 60);

        var seed = new byte[64];
        clientRandom.CopyTo(seed, 0);
        serverRandom.CopyTo(seed, 32);
        exported.Should().Equal(TlsPrf.Prf(master, "EXTRACTOR-dtls_srtp", seed, 60));
        exported.Should().HaveCount(60);
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result, 0);
        b.CopyTo(result, a.Length);
        return result;
    }

    /// <summary>
    /// RFC 5246 §8.1: <c>master_secret = PRF(pms, "master secret", ClientHello.random +
    /// ServerHello.random)</c> — client random FIRST, the opposite of key expansion. Two Keryx peers
    /// would interoperate perfectly with the order swapped, so nothing but a structural assertion can
    /// catch it.
    /// </summary>
    [Fact]
    public void Master_secret_seed_order_is_client_random_then_server_random()
    {
        var preMasterSecret = new byte[32];
        preMasterSecret[0] = 0x11;
        var clientRandom = new byte[32];
        var serverRandom = new byte[32];
        clientRandom[31] = 1;
        serverRandom[31] = 2;

        var master = TlsPrf.MasterSecret(preMasterSecret, clientRandom, serverRandom);

        var seed = new byte[64];
        clientRandom.CopyTo(seed, 0);
        serverRandom.CopyTo(seed, 32);
        master.Should().Equal(TlsPrf.Prf(preMasterSecret, "master secret", seed, 48));
        master.Should().HaveCount(48);

        // And the reversed order must give something different, so the assertion above has teeth.
        var reversed = new byte[64];
        serverRandom.CopyTo(reversed, 0);
        clientRandom.CopyTo(reversed, 32);
        master.Should().NotEqual(TlsPrf.Prf(preMasterSecret, "master secret", reversed, 48));
    }

    /// <summary>
    /// RFC 7627 §4: the extended master secret is derived from the handshake <c>session_hash</c> with
    /// the label <c>"extended master secret"</c> and no randoms at all.
    /// </summary>
    [Fact]
    public void Extended_master_secret_uses_the_session_hash_and_no_randoms()
    {
        var preMasterSecret = new byte[32];
        preMasterSecret[5] = 0x77;
        var sessionHash = new byte[32];
        sessionHash[0] = 0xAB;

        var master = TlsPrf.ExtendedMasterSecret(preMasterSecret, sessionHash);

        master.Should().Equal(TlsPrf.Prf(preMasterSecret, "extended master secret", sessionHash, 48));
        master.Should().HaveCount(48);
    }

    /// <summary>
    /// RFC 5246 §7.4.9: <c>verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))
    /// [0..11]</c> — twelve bytes, and the two labels are "client finished" and "server finished".
    /// Swapping both labels leaves two Keryx peers interoperating, so this is pinned directly.
    /// </summary>
    [Fact]
    public void Verify_data_is_twelve_bytes_under_the_rfc5246_finished_labels()
    {
        var master = new byte[48];
        master[2] = 0x5A;
        var transcriptHash = new byte[32];
        transcriptHash[31] = 0xC3;

        TlsPrf.ClientFinishedLabel.Should().Be("client finished");
        TlsPrf.ServerFinishedLabel.Should().Be("server finished");

        var client = TlsPrf.VerifyData(master, TlsPrf.ClientFinishedLabel, transcriptHash);
        var server = TlsPrf.VerifyData(master, TlsPrf.ServerFinishedLabel, transcriptHash);

        client.Should().HaveCount(12);
        server.Should().HaveCount(12);
        client.Should().Equal(TlsPrf.Prf(master, "client finished", transcriptHash, 12));
        server.Should().Equal(TlsPrf.Prf(master, "server finished", transcriptHash, 12));
        client.Should().NotEqual(server, "the two directions must not share verify_data");
    }

    /// <summary>
    /// RFC 5246 §8.1 and §6.3 use opposite random orders, and RFC 5705 §4 agrees with §8.1 rather
    /// than §6.3. Getting any one of the three wrong is invisible to a Keryx-to-Keryx handshake, so
    /// this pins that the three derivations really are distinct from one another.
    /// </summary>
    [Fact]
    public void The_three_derivations_do_not_share_a_seed_order()
    {
        var secret = new byte[48];
        secret[0] = 0x3C;
        var clientRandom = new byte[32];
        var serverRandom = new byte[32];
        clientRandom[0] = 0xAA;
        serverRandom[0] = 0xBB;

        var master = TlsPrf.MasterSecret(secret, clientRandom, serverRandom);
        var keyBlock = TlsPrf.KeyBlock(secret, clientRandom, serverRandom, 48);
        var exported = TlsPrf.ExportKeyingMaterial(secret, "EXTRACTOR-dtls_srtp", clientRandom, serverRandom, 48);

        master.Should().NotEqual(keyBlock);
        master.Should().NotEqual(exported, "same seed order, but a different label must still separate them");
        keyBlock.Should().NotEqual(exported);
    }
}
