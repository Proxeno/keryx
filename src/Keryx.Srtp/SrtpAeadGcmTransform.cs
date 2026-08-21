using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Keryx.Srtp;

/// <summary>
/// <c>SRTP_AEAD_AES_128_GCM</c> (RFC 7714): AES-GCM over the RTP payload with the RTP header as
/// additional authenticated data, keyed by the RFC 3711 AES-CM PRF (RFC 7714 Section 11).
/// </summary>
internal sealed class SrtpAeadGcmTransform : ISrtpTransform
{
    /// <summary>Length of the GCM nonce for SRTP and SRTCP (RFC 7714 Sections 8.1 and 9.1).</summary>
    public const int NonceLength = 12;

    private const int RtcpAadLength = RtpHeaderView.RtcpHeaderLength + SrtpProtectionProfile.SrtcpIndexLength;

    private readonly int _tagLength;
    private readonly AesGcm _rtpCipher;
    private readonly AesGcm _rtcpCipher;
    private readonly byte[] _rtpSalt;
    private readonly byte[] _rtcpSalt;
    private byte[] _scratch = [];
    private bool _disposed;

    public SrtpAeadGcmTransform(SrtpProtectionProfile profile, SrtpSessionKeys keys, ulong keyDerivationRate)
    {
        _tagLength = profile.TagLength;
        _rtpSalt = new byte[profile.SessionSaltLength];
        _rtcpSalt = new byte[profile.SessionSaltLength];

        var masterSalt = keys.MasterSalt.Span;
        Span<byte> encryptionKey = stackalloc byte[profile.MasterKeyLength];
        try
        {
            using var prf = new AesCounterMode(keys.MasterKey.Span);

            SrtpKeyDerivation.Derive(prf, masterSalt, SrtpKeyDerivation.SrtpEncryptionLabel, 0, keyDerivationRate, encryptionKey);
            _rtpCipher = new AesGcm(encryptionKey, _tagLength);
            SrtpKeyDerivation.Derive(prf, masterSalt, SrtpKeyDerivation.SrtpSaltLabel, 0, keyDerivationRate, _rtpSalt);

            SrtpKeyDerivation.Derive(prf, masterSalt, SrtpKeyDerivation.SrtcpEncryptionLabel, 0, keyDerivationRate, encryptionKey);
            _rtcpCipher = new AesGcm(encryptionKey, _tagLength);
            SrtpKeyDerivation.Derive(prf, masterSalt, SrtpKeyDerivation.SrtcpSaltLabel, 0, keyDerivationRate, _rtcpSalt);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encryptionKey);
        }
    }

    /// <summary>
    /// Test/diagnostic constructor taking already-derived session material, so the RFC 7714
    /// Section 16 and 17 vectors (which publish session keys, not master keys) can be reproduced.
    /// </summary>
    public SrtpAeadGcmTransform(
        ReadOnlySpan<byte> sessionKey,
        ReadOnlySpan<byte> sessionSalt,
        ReadOnlySpan<byte> rtcpSessionKey,
        ReadOnlySpan<byte> rtcpSessionSalt,
        int tagLength)
    {
        _tagLength = tagLength;
        _rtpCipher = new AesGcm(sessionKey, tagLength);
        _rtcpCipher = new AesGcm(rtcpSessionKey, tagLength);
        _rtpSalt = sessionSalt.ToArray();
        _rtcpSalt = rtcpSessionSalt.ToArray();
    }

    public int RtpOverhead => _tagLength;

    public int RtcpOverhead => SrtpProtectionProfile.SrtcpIndexLength + _tagLength;

    public int MinimumProtectedRtcpLength => RtpHeaderView.RtcpHeaderLength + RtcpOverhead;

    public int SrtcpIndexWordOffset(int packetLength) =>
        packetLength - SrtpProtectionProfile.SrtcpIndexLength;

    /// <summary>
    /// RFC 7714 Section 8.1: the IV is <c>(00 00 || SSRC || ROC || SEQ) XOR salt</c>.
    /// </summary>
    internal static void BuildRtpNonce(
        ReadOnlySpan<byte> salt,
        uint ssrc,
        uint rolloverCounter,
        ushort sequenceNumber,
        Span<byte> nonce)
    {
        nonce.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(nonce.Slice(2, 4), ssrc);
        BinaryPrimitives.WriteUInt32BigEndian(nonce.Slice(6, 4), rolloverCounter);
        BinaryPrimitives.WriteUInt16BigEndian(nonce.Slice(10, 2), sequenceNumber);
        for (var i = 0; i < salt.Length && i < nonce.Length; i++)
        {
            nonce[i] ^= salt[i];
        }
    }

    /// <summary>
    /// RFC 7714 Section 9.1: the IV is <c>(00 00 || SSRC || 00 00 || 0 || SRTCP index) XOR salt</c>.
    /// </summary>
    internal static void BuildRtcpNonce(ReadOnlySpan<byte> salt, uint ssrc, uint index, Span<byte> nonce)
    {
        nonce.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(nonce.Slice(2, 4), ssrc);
        BinaryPrimitives.WriteUInt32BigEndian(nonce.Slice(8, 4), index & SrtcpIndexWord.IndexMask);
        for (var i = 0; i < salt.Length && i < nonce.Length; i++)
        {
            nonce[i] ^= salt[i];
        }
    }

    public int ProtectRtp(
        ReadOnlySpan<byte> packet,
        int headerLength,
        uint ssrc,
        uint rolloverCounter,
        ushort sequenceNumber,
        Span<byte> output)
    {
        var length = packet.Length;
        Span<byte> nonce = stackalloc byte[NonceLength];
        BuildRtpNonce(_rtpSalt, ssrc, rolloverCounter, sequenceNumber, nonce);

        _rtpCipher.Encrypt(
            nonce,
            packet[headerLength..],
            output[headerLength..length],
            output.Slice(length, _tagLength),
            packet[..headerLength]);

        packet[..headerLength].CopyTo(output);
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
        var cipherEnd = packet.Length - _tagLength;
        var plaintextLength = cipherEnd - headerLength;
        if (plaintextLength < 0)
        {
            return false;
        }

        Span<byte> nonce = stackalloc byte[NonceLength];
        BuildRtpNonce(_rtpSalt, ssrc, rolloverCounter, sequenceNumber, nonce);

        try
        {
            _rtpCipher.Decrypt(
                nonce,
                packet[headerLength..cipherEnd],
                packet[cipherEnd..],
                output.Slice(headerLength, plaintextLength),
                packet[..headerLength]);
        }
        catch (AuthenticationTagMismatchException)
        {
            return false;
        }

        packet[..headerLength].CopyTo(output);
        length = cipherEnd;
        return true;
    }

    public int ProtectRtcp(ReadOnlySpan<byte> packet, uint ssrc, uint index, bool encrypt, Span<byte> output)
    {
        var length = packet.Length;
        var indexWord = SrtcpIndexWord.Encode(index, encrypt);

        Span<byte> nonce = stackalloc byte[NonceLength];
        BuildRtcpNonce(_rtcpSalt, ssrc, index, nonce);

        if (encrypt)
        {
            // RFC 7714 Section 17: AAD = first 8 octets of the RTCP packet || ESRTCP word.
            Span<byte> aad = stackalloc byte[RtcpAadLength];
            packet[..RtpHeaderView.RtcpHeaderLength].CopyTo(aad);
            BinaryPrimitives.WriteUInt32BigEndian(aad[RtpHeaderView.RtcpHeaderLength..], indexWord);

            _rtcpCipher.Encrypt(
                nonce,
                packet[RtpHeaderView.RtcpHeaderLength..],
                output[RtpHeaderView.RtcpHeaderLength..length],
                output.Slice(length, _tagLength),
                aad);

            packet[..RtpHeaderView.RtcpHeaderLength].CopyTo(output);
            BinaryPrimitives.WriteUInt32BigEndian(output.Slice(length + _tagLength, 4), indexWord);
            return length + _tagLength + SrtpProtectionProfile.SrtcpIndexLength;
        }

        // E = 0: the whole cleartext packet plus the ESRTCP word is the AAD and the cipher is the
        // tag alone (RFC 7714 Section 17).
        var aadLength = length + SrtpProtectionProfile.SrtcpIndexLength;
        EnsureScratch(aadLength);
        var scratch = _scratch.AsSpan(0, aadLength);
        packet.CopyTo(scratch);
        BinaryPrimitives.WriteUInt32BigEndian(scratch[length..], indexWord);

        _rtcpCipher.Encrypt(
            nonce,
            ReadOnlySpan<byte>.Empty,
            Span<byte>.Empty,
            output.Slice(length, _tagLength),
            scratch);

        packet.CopyTo(output);
        BinaryPrimitives.WriteUInt32BigEndian(output.Slice(length + _tagLength, 4), indexWord);
        return length + _tagLength + SrtpProtectionProfile.SrtcpIndexLength;
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
        var indexWordOffset = packet.Length - SrtpProtectionProfile.SrtcpIndexLength;
        var indexWord = SrtcpIndexWord.Encode(index, encrypted);

        Span<byte> nonce = stackalloc byte[NonceLength];
        BuildRtcpNonce(_rtcpSalt, ssrc, index, nonce);

        var tagOffset = indexWordOffset - _tagLength;
        if (encrypted)
        {
            var plaintextLength = tagOffset - RtpHeaderView.RtcpHeaderLength;
            if (plaintextLength < 0)
            {
                return false;
            }

            Span<byte> aad = stackalloc byte[RtcpAadLength];
            packet[..RtpHeaderView.RtcpHeaderLength].CopyTo(aad);
            BinaryPrimitives.WriteUInt32BigEndian(aad[RtpHeaderView.RtcpHeaderLength..], indexWord);

            try
            {
                _rtcpCipher.Decrypt(
                    nonce,
                    packet[RtpHeaderView.RtcpHeaderLength..tagOffset],
                    packet.Slice(tagOffset, _tagLength),
                    output.Slice(RtpHeaderView.RtcpHeaderLength, plaintextLength),
                    aad);
            }
            catch (AuthenticationTagMismatchException)
            {
                return false;
            }

            packet[..RtpHeaderView.RtcpHeaderLength].CopyTo(output);
            length = tagOffset;
            return true;
        }

        // E = 0: the cipher is the tag alone and the whole cleartext RTCP packet is part of the AAD
        // (RFC 7714 Section 17). The AAD is not contiguous on the wire, so it is reassembled here.
        var rtcpLength = tagOffset;
        if (rtcpLength < RtpHeaderView.RtcpHeaderLength)
        {
            return false;
        }

        var aadLength = rtcpLength + SrtpProtectionProfile.SrtcpIndexLength;
        EnsureScratch(aadLength);
        var scratch = _scratch.AsSpan(0, aadLength);
        packet[..rtcpLength].CopyTo(scratch);
        BinaryPrimitives.WriteUInt32BigEndian(scratch[rtcpLength..], indexWord);

        try
        {
            _rtcpCipher.Decrypt(
                nonce,
                ReadOnlySpan<byte>.Empty,
                packet.Slice(tagOffset, _tagLength),
                Span<byte>.Empty,
                scratch);
        }
        catch (AuthenticationTagMismatchException)
        {
            return false;
        }

        packet[..rtcpLength].CopyTo(output);
        length = rtcpLength;
        return true;
    }

    private void EnsureScratch(int required)
    {
        if (_scratch.Length < required)
        {
            _scratch = new byte[Math.Max(required, 256)];
        }
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
    }
}
