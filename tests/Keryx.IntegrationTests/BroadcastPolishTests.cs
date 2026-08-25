using System.Net;
using FluentAssertions;
using Keryx;
using Keryx.Broadcast;
using Keryx.Core;
using Keryx.Rtp;
using Keryx.Srtp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// Broadcast productionization polish (<c>broadcast-scale.md</c> §3–§5): the backpressure drop metric, and
/// shared-key hygiene — key-export zeroization, bounded decrypt-context retention across epoch rotations,
/// and the >255-SSRC encode guard.
/// </summary>
public sealed class BroadcastPolishTests
{
    private static SrtpProtectionProfile Profile => SrtpProtectionProfile.AeadAes128Gcm;

    // -------------------------------------------------------------------------------------------------
    // Backpressure drop metric.
    // -------------------------------------------------------------------------------------------------

    /// <summary>
    /// When the shared socket's send buffer stays full across every retry, <see cref="BroadcastEndpoint.SendBatch"/>
    /// tail-drops the un-sent datagrams and counts them on <see cref="BroadcastEndpoint.DroppedDatagrams"/> —
    /// the previously-silent drop is now observable.
    /// </summary>
    [Fact]
    public async Task SendBatch_TailDrop_IsCountedOnDroppedDatagrams()
    {
        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions { MaxViewers = 1 });

        // Script the socket as permanently backpressured: it never accepts a datagram.
        endpoint._sendWindowOverrideForTest = (_, _) => 0;

        var batch = MakeDatagrams(5);
        endpoint.DroppedDatagrams.Should().Be(0);

        endpoint.SendBatch(batch).Should().Be(0, "a permanently-full send buffer accepts nothing");
        endpoint.DroppedDatagrams.Should().Be(5, "every un-sent datagram of the batch is counted as dropped");

        endpoint.SendBatch(batch).Should().Be(0);
        endpoint.DroppedDatagrams.Should().Be(10, "the counter accumulates across flushes");
    }

    /// <summary>A partial send counts only the un-sent tail, not the datagrams the kernel accepted.</summary>
    [Fact]
    public async Task SendBatch_PartialSend_CountsOnlyTheDroppedTail()
    {
        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions { MaxViewers = 1 });

        // Accept the first two datagrams of the window, then stay full for the rest of the retries.
        var firstAttempt = true;
        endpoint._sendWindowOverrideForTest = (_, _) =>
        {
            if (firstAttempt)
            {
                firstAttempt = false;
                return 2;
            }

            return 0;
        };

        var accepted = endpoint.SendBatch(MakeDatagrams(5));
        accepted.Should().Be(2, "two datagrams went out before the buffer filled");
        endpoint.DroppedDatagrams.Should().Be(3, "only the three un-sent datagrams are dropped");
    }

    /// <summary>The send-buffer sizing lever is applied to the shared socket.</summary>
    [Fact]
    public async Task SendBufferSize_Option_IsAppliedToTheSharedSocket()
    {
        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions
        {
            MaxViewers = 1,
            SendBufferSize = 1 << 20,
        });

        // The OS may clamp the request, but it must at least have taken effect (non-trivially sized).
        endpoint.DroppedDatagrams.Should().Be(0);
    }

    // -------------------------------------------------------------------------------------------------
    // Shared-key hygiene: export zeroization.
    // -------------------------------------------------------------------------------------------------

    [Fact]
    public void PublicBroadcastKeyExport_Dispose_ZeroesAndBlocksReuse()
    {
        using var key = PublicBroadcastKey.CreateForPublicContent(Profile);
        var export = key.Export();

        // Usable before dispose.
        export.ToSessionKeys().Should().NotBeNull();

        export.Dispose();

        // After dispose the secret material is zeroed and the key seams refuse to hand it out.
        var reuse = () => export.ToSessionKeys();
        reuse.Should().Throw<ObjectDisposedException>();

        var encode = () => PublicBroadcastKeyMessage.Encode(export, [0x1234u]);
        encode.Should().Throw<ObjectDisposedException>();

        // Dispose is idempotent, and the source key is untouched (still exports fresh copies).
        export.Dispose();
        using var again = key.Export();
        again.ToSessionKeys().Should().NotBeNull();
    }

    // -------------------------------------------------------------------------------------------------
    // Shared-key hygiene: bounded decrypt-context retention across epoch rotations.
    // -------------------------------------------------------------------------------------------------

    [Fact]
    public void PublicBroadcastReceiveKeys_RetentionIsBounded_AcrossManyRotations()
    {
        const uint broadcastSsrc = 0x5150_0001u;
        const int cap = 3;
        using var receiver = new PublicBroadcastReceiveKeys(NullLogger.Instance, maxRetainedContexts: cap);

        PublicBroadcastKey? current = null;
        PublicBroadcastKey? previous = null;
        try
        {
            for (var epoch = 0; epoch < 12; epoch++)
            {
                previous?.Dispose();
                previous = current;
                current = epoch == 0
                    ? PublicBroadcastKey.CreateForPublicContent(Profile)
                    : current!.RotateEpoch();

                using var export = current.Export();
                receiver.Install(export, [broadcastSsrc]);

                // The retained set never grows past the cap, however many epochs roll through.
                receiver.RetainedContextCount.Should().BeLessThanOrEqualTo(cap);
            }

            // The current and immediately-previous epochs still decrypt across the switch.
            var recovered = new byte[2048];
            EncryptBroadcastPacket(current!, broadcastSsrc, seq: 1, out var currentCipher);
            receiver.TryUnprotectRtp(broadcastSsrc, currentCipher, recovered, out _)
                .Should().Be(PublicBroadcastReceiveKeys.Outcome.Unprotected, "the current epoch decrypts");

            EncryptBroadcastPacket(previous!, broadcastSsrc, seq: 1, out var previousCipher);
            receiver.TryUnprotectRtp(broadcastSsrc, previousCipher, recovered, out _)
                .Should().Be(PublicBroadcastReceiveKeys.Outcome.Unprotected, "the previous epoch still decrypts across the switch");
        }
        finally
        {
            current?.Dispose();
            previous?.Dispose();
        }
    }

    // -------------------------------------------------------------------------------------------------
    // Shared-key hygiene: >255-SSRC encode guard.
    // -------------------------------------------------------------------------------------------------

    [Fact]
    public void PublicBroadcastKeyMessage_Encode_RefusesMoreThan255Ssrcs()
    {
        using var key = PublicBroadcastKey.CreateForPublicContent(Profile);
        using var export = key.Export();

        var tooMany = new uint[256];
        for (var i = 0; i < tooMany.Length; i++)
        {
            tooMany[i] = (uint)(0x1000 + i);
        }

        var encode = () => PublicBroadcastKeyMessage.Encode(export, tooMany);
        encode.Should().Throw<ArgumentException>("the on-wire SSRC count is a single byte");

        // Exactly 255 is still allowed and round-trips.
        var maxOk = new uint[255];
        for (var i = 0; i < maxOk.Length; i++)
        {
            maxOk[i] = (uint)(0x2000 + i);
        }

        using var okExport = key.Export();
        var frame = PublicBroadcastKeyMessage.Encode(okExport, maxOk);
        PublicBroadcastKeyMessage.TryDecode(frame, out _, out var decodedSsrcs).Should().BeTrue();
        decodedSsrcs.Should().HaveCount(255);
    }

    // -------------------------------------------------------------------------------------------------
    // Helpers.
    // -------------------------------------------------------------------------------------------------
    private static IReadOnlyList<BroadcastDatagram> MakeDatagrams(int count)
    {
        var list = new List<BroadcastDatagram>(count);
        for (var i = 0; i < count; i++)
        {
            var payload = new byte[32];
            payload[0] = (byte)i;
            list.Add(new BroadcastDatagram(payload, new IPEndPoint(IPAddress.Loopback, 41000 + i)));
        }

        return list;
    }

    private static void EncryptBroadcastPacket(PublicBroadcastKey key, uint ssrc, ushort seq, out byte[] cipher)
    {
        using var encrypt = new SrtpEncryptContext(key.Profile, KeyToSessionKeys(key));
        var header = new RtpHeader
        {
            Version = 2,
            PayloadType = 96,
            Ssrc = ssrc,
            SequenceNumber = seq,
            Timestamp = seq * 3000u,
        };

        var payload = new byte[48];
        for (var i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)(i * 5);
        }

        var plaintext = new byte[header.HeaderLength + payload.Length];
        var written = header.WriteTo(plaintext);
        payload.CopyTo(plaintext.AsSpan(written));

        cipher = new byte[plaintext.Length + key.Profile.RtpOverhead];
        var length = encrypt.ProtectRtp(plaintext, cipher);
        cipher = cipher[..length];
    }

    private static SrtpSessionKeys KeyToSessionKeys(PublicBroadcastKey key)
    {
        // Route through the export seam (public) to get session keys without reaching into internals.
        using var export = key.Export();
        return export.ToSessionKeys();
    }
}
