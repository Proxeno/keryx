using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Keryx.Srtp;

/// <summary>
/// <c>SRTP_AES128_CM_HMAC_SHA1_80</c>: AES-128 counter mode (RFC 3711 Section 4.1.1) with
/// HMAC-SHA1 truncated to 80 bits (RFC 3711 Section 4.2.1), keyed by the Section 4.3 key
/// derivation.
/// </summary>
internal sealed class SrtpAesCmHmacSha1Transform : ISrtpTransform
{
    private const int HmacSha1Length = 20;

    private readonly int _tagLength;
    private readonly AesCounterMode _rtpCipher;
    private readonly AesCounterMode _rtcpCipher;
    private readonly byte[] _rtpSalt;
    private readonly byte[] _rtcpSalt;
    private readonly byte[] _rtpAuthKey;
    private readonly byte[] _rtcpAuthKey;
    private bool _disposed;

    public SrtpAesCmHmacSha1Transform(SrtpProtectionProfile profile, SrtpSessionKeys keys, ulong keyDerivationRate)
    {
        _tagLength = profile.TagLength;
        _rtpSalt = new byte[profile.SessionSaltLength];
        _rtcpSalt = new byte[profile.SessionSaltLength];
        _rtpAuthKey = new byte[profile.AuthenticationKeyLength];
        _rtcpAuthKey = new byte[profile.AuthenticationKeyLength];

        var masterKey = keys.MasterKey.Span;
        var masterSalt = keys.MasterSalt.Span;

        Span<byte> encryptionKey = stackalloc byte[profile.MasterKeyLength];
        try
        {
            using var prf = new AesCounterMode(masterKey);

            // RFC 3711 Section 4.3.1: labels 0x00/0x01/0x02 for SRTP.
            SrtpKeyDerivation.Derive(prf, masterSalt, SrtpKeyDerivation.SrtpEncryptionLabel, 0, keyDerivationRate, encryptionKey);
            _rtpCipher = new AesCounterMode(encryptionKey);
            SrtpKeyDerivation.Derive(prf, masterSalt, SrtpKeyDerivation.SrtpAuthenticationLabel, 0, keyDerivationRate, _rtpAuthKey);
            SrtpKeyDerivation.Derive(prf, masterSalt, SrtpKeyDerivation.SrtpSaltLabel, 0, keyDerivationRate, _rtpSalt);

            // RFC 3711 Section 4.3.2: labels 0x03/0x04/0x05 for SRTCP.
            SrtpKeyDerivation.Derive(prf, masterSalt, SrtpKeyDerivation.SrtcpEncryptionLabel, 0, keyDerivationRate, encryptionKey);
            _rtcpCipher = new AesCounterMode(encryptionKey);
            SrtpKeyDerivation.Derive(prf, masterSalt, SrtpKeyDerivation.SrtcpAuthenticationLabel, 0, keyDerivationRate, _rtcpAuthKey);
            SrtpKeyDerivation.Derive(prf, masterSalt, SrtpKeyDerivation.SrtcpSaltLabel, 0, keyDerivationRate, _rtcpSalt);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encryptionKey);
        }
    }

    public int RtpOverhead => _tagLength;

    public int RtcpOverhead => SrtpProtectionProfile.SrtcpIndexLength + _tagLength;

    public int MinimumProtectedRtcpLength => RtpHeaderView.RtcpHeaderLength + RtcpOverhead;

    public int SrtcpIndexWordOffset(int packetLength) =>
        packetLength - _tagLength - SrtpProtectionProfile.SrtcpIndexLength;

    public int ProtectRtp(
        ReadOnlySpan<byte> packet,
        int headerLength,
        uint ssrc,
        uint rolloverCounter,
        ushort sequenceNumber,
        Span<byte> output)
    {
        var length = packet.Length;
        packet[..headerLength].CopyTo(output);

        Span<byte> iv = stackalloc byte[AesCounterMode.BlockSize];
        AesCounterMode.BuildPacketIv(_rtpSalt, ssrc, SrtpPacketIndex.Compose(rolloverCounter, sequenceNumber), iv);
        _rtpCipher.Transform(iv, packet[headerLength..], output[headerLength..length]);

        // RFC 3711 Section 4.2: M = Authenticated Portion || ROC. The ROC is written into the tag
        // room, hashed, then overwritten by the tag itself.
        BinaryPrimitives.WriteUInt32BigEndian(output.Slice(length, 4), rolloverCounter);
        Span<byte> mac = stackalloc byte[HmacSha1Length];
        HMACSHA1.HashData(_rtpAuthKey, output[..(length + 4)], mac);
        mac[.._tagLength].CopyTo(output[length..]);

        return length + _tagLength;
    }

    public bool TryUnprotectRtp(
        ReadOnlySpan<byte> packet,
        int headerLength,
        uint ssrc,
        uint rolloverCounter,
        ushort sequenceNumber,
        Span<byte> output,
        out int length)
    {
        length = 0;
        var bodyLength = packet.Length - _tagLength;

        Span<byte> receivedTag = stackalloc byte[HmacSha1Length];
        packet[bodyLength..].CopyTo(receivedTag);

        // Copy the authenticated portion into the output buffer so the ROC can be appended for
        // hashing without mutating the caller's read-only input.
        packet[..bodyLength].CopyTo(output);
        BinaryPrimitives.WriteUInt32BigEndian(output.Slice(bodyLength, 4), rolloverCounter);

        Span<byte> mac = stackalloc byte[HmacSha1Length];
        HMACSHA1.HashData(_rtpAuthKey, output[..(bodyLength + 4)], mac);

        if (!CryptographicOperations.FixedTimeEquals(mac[.._tagLength], receivedTag[.._tagLength]))
        {
            return false;
        }

        Span<byte> iv = stackalloc byte[AesCounterMode.BlockSize];
        AesCounterMode.BuildPacketIv(_rtpSalt, ssrc, SrtpPacketIndex.Compose(rolloverCounter, sequenceNumber), iv);
        _rtpCipher.Transform(iv, output[headerLength..bodyLength], output[headerLength..bodyLength]);

        output.Slice(bodyLength, 4).Clear();
        length = bodyLength;
        return true;
    }

    public int ProtectRtcp(ReadOnlySpan<byte> packet, uint ssrc, uint index, bool encrypt, Span<byte> output)
    {
        var length = packet.Length;
        packet[..RtpHeaderView.RtcpHeaderLength].CopyTo(output);

        // RFC 3711 Section 3.4: the Encrypted Portion starts at the ninth octet.
        if (encrypt)
        {
            Span<byte> iv = stackalloc byte[AesCounterMode.BlockSize];
            AesCounterMode.BuildPacketIv(_rtcpSalt, ssrc, index, iv);
            _rtcpCipher.Transform(
                iv,
                packet[RtpHeaderView.RtcpHeaderLength..],
                output[RtpHeaderView.RtcpHeaderLength..length]);
        }
        else
        {
            packet[RtpHeaderView.RtcpHeaderLength..].CopyTo(output[RtpHeaderView.RtcpHeaderLength..length]);
        }

        BinaryPrimitives.WriteUInt32BigEndian(output.Slice(length, 4), SrtcpIndexWord.Encode(index, encrypt));

        // The Authenticated Portion is the whole packet including the E-flag/index word.
        Span<byte> mac = stackalloc byte[HmacSha1Length];
        HMACSHA1.HashData(_rtcpAuthKey, output[..(length + 4)], mac);
        mac[.._tagLength].CopyTo(output[(length + 4)..]);

        return length + 4 + _tagLength;
    }

    public bool TryUnprotectRtcp(
        ReadOnlySpan<byte> packet,
        uint ssrc,
        uint index,
        bool encrypted,
        Span<byte> output,
        out int length)
    {
        length = 0;
        var authenticatedLength = packet.Length - _tagLength;

        Span<byte> mac = stackalloc byte[HmacSha1Length];
        HMACSHA1.HashData(_rtcpAuthKey, packet[..authenticatedLength], mac);
        if (!CryptographicOperations.FixedTimeEquals(mac[.._tagLength], packet[authenticatedLength..]))
        {
            return false;
        }

        var rtcpLength = authenticatedLength - SrtpProtectionProfile.SrtcpIndexLength;
        packet[..rtcpLength].CopyTo(output);

        if (encrypted)
        {
            Span<byte> iv = stackalloc byte[AesCounterMode.BlockSize];
            AesCounterMode.BuildPacketIv(_rtcpSalt, ssrc, index, iv);
            _rtcpCipher.Transform(
                iv,
                output[RtpHeaderView.RtcpHeaderLength..rtcpLength],
                output[RtpHeaderView.RtcpHeaderLength..rtcpLength]);
        }

        length = rtcpLength;
        return true;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _rtpCipher.Dispose();
        _rtcpCipher.Dispose();
        CryptographicOperations.ZeroMemory(_rtpSalt);
        CryptographicOperations.ZeroMemory(_rtcpSalt);
        CryptographicOperations.ZeroMemory(_rtpAuthKey);
        CryptographicOperations.ZeroMemory(_rtcpAuthKey);
    }
}
