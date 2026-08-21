using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Cryptography;
using Keryx.Core;

namespace Keryx.Stun;

/// <summary>
/// A STUN message: a 20-byte header (type, length, magic cookie, 96-bit transaction id) followed
/// by a sequence of type-length-value attributes padded to four-byte boundaries (RFC 5389).
/// </summary>
/// <remarks>
/// <para>
/// MESSAGE-INTEGRITY and FINGERPRINT are not ordinary attributes: their values cover the bytes
/// that precede them, and the header length field must, while they are being computed, already
/// count the attribute being computed. <see cref="Encode(byte[], bool)"/> handles that dummy-length
/// rule and always appends them last, in that order, ignoring any instance the caller put in
/// <see cref="Attributes"/>.
/// </para>
/// <para>
/// Decoded messages retain the exact bytes they were parsed from in <see cref="Raw"/>, because
/// integrity verification must run against the received bytes rather than a re-encoding (padding
/// bytes may legally differ under RFC 5389, and re-encoding would change the digest).
/// </para>
/// </remarks>
public sealed class StunMessage
{
    /// <summary>The STUN magic cookie, at offset 4 of every message (RFC 5389 section 6).</summary>
    public const uint MagicCookie = 0x2112A442u;

    /// <summary>Length of the fixed STUN header in bytes.</summary>
    public const int HeaderLength = 20;

    private const ushort MessageIntegrityCode = (ushort)StunAttributeType.MessageIntegrity;
    private const ushort FingerprintCode = (ushort)StunAttributeType.Fingerprint;
    private const int MessageIntegrityAttributeLength = 4 + StunMessageIntegrityAttribute.DigestLength;
    private const int FingerprintAttributeLength = 8;

    private byte[]? _raw;

    /// <summary>Creates a message with a freshly generated random transaction id.</summary>
    /// <param name="messageClass">The message class.</param>
    /// <param name="method">The message method.</param>
    public StunMessage(StunClass messageClass, StunMethod method)
        : this(messageClass, method, StunTransactionId.NewRandom())
    {
    }

    /// <summary>Creates a message with an explicit transaction id.</summary>
    /// <param name="messageClass">The message class.</param>
    /// <param name="method">The message method.</param>
    /// <param name="transactionId">The 96-bit transaction id.</param>
    public StunMessage(StunClass messageClass, StunMethod method, StunTransactionId transactionId)
    {
        Class = messageClass;
        Method = method;
        TransactionId = transactionId;
        Attributes = [];
    }

    /// <summary>The message class.</summary>
    public StunClass Class { get; }

    /// <summary>The message method.</summary>
    public StunMethod Method { get; }

    /// <summary>The 96-bit transaction id.</summary>
    public StunTransactionId TransactionId { get; }

    /// <summary>
    /// The message's attributes, in wire order. Mutable; MESSAGE-INTEGRITY and FINGERPRINT
    /// instances found here are skipped by <see cref="Encode(byte[], bool)"/>.
    /// </summary>
    public List<StunAttribute> Attributes { get; }

    /// <summary>
    /// The exact bytes this message was decoded from, or the bytes most recently produced by
    /// <see cref="Encode(byte[], bool)"/>; empty if the message has never been encoded or decoded.
    /// </summary>
    public ReadOnlyMemory<byte> Raw => _raw ?? ReadOnlyMemory<byte>.Empty;

    /// <summary>The 16-bit message type as it appears on the wire.</summary>
    public ushort MessageType => EncodeMessageType(Class, Method);

    /// <summary>True when the message is a success or error response.</summary>
    public bool IsResponse => Class is StunClass.SuccessResponse or StunClass.ErrorResponse;

    /// <summary>Creates a Binding request with a random transaction id.</summary>
    public static StunMessage CreateBindingRequest() => new(StunClass.Request, StunMethod.Binding);

    /// <summary>Creates a Binding indication with a random transaction id.</summary>
    public static StunMessage CreateBindingIndication() => new(StunClass.Indication, StunMethod.Binding);

    /// <summary>Creates a success response echoing <paramref name="request"/>'s method and transaction id.</summary>
    /// <param name="request">The request being answered.</param>
    public static StunMessage CreateSuccessResponse(StunMessage request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return new StunMessage(StunClass.SuccessResponse, request.Method, request.TransactionId);
    }

    /// <summary>Creates an error response carrying an ERROR-CODE attribute.</summary>
    /// <param name="request">The request being answered.</param>
    /// <param name="code">The error code, for example 400 or 487.</param>
    /// <param name="reason">The reason phrase.</param>
    public static StunMessage CreateErrorResponse(StunMessage request, int code, string reason)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new StunMessage(StunClass.ErrorResponse, request.Method, request.TransactionId);
        response.Attributes.Add(new StunErrorCodeAttribute(code, reason));
        return response;
    }

    /// <summary>Appends an attribute and returns this message, for fluent construction.</summary>
    /// <param name="attribute">The attribute to append.</param>
    public StunMessage Add(StunAttribute attribute)
    {
        ArgumentNullException.ThrowIfNull(attribute);
        Attributes.Add(attribute);
        return this;
    }

    /// <summary>Returns the first attribute of type <typeparamref name="T"/>, or null.</summary>
    /// <typeparam name="T">The attribute class to look for.</typeparam>
    public T? GetAttribute<T>()
        where T : StunAttribute
    {
        foreach (var attribute in Attributes)
        {
            if (attribute is T typed)
            {
                return typed;
            }
        }

        return null;
    }

    /// <summary>True when an attribute with the given type code is present.</summary>
    /// <param name="type">The attribute type code.</param>
    public bool HasAttribute(StunAttributeType type)
    {
        foreach (var attribute in Attributes)
        {
            if (attribute.Type == type)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// The reflexive transport address: XOR-MAPPED-ADDRESS if present, otherwise MAPPED-ADDRESS,
    /// otherwise null.
    /// </summary>
    public IPEndPoint? MappedAddress
        => GetAttribute<StunXorMappedAddressAttribute>()?.EndPoint
           ?? GetAttribute<StunMappedAddressAttribute>()?.EndPoint;

    /// <summary>The USERNAME attribute's value, or null.</summary>
    public string? Username => GetAttribute<StunUsernameAttribute>()?.Value;

    /// <summary>The ERROR-CODE attribute's code, or null.</summary>
    public int? ErrorCode => GetAttribute<StunErrorCodeAttribute>()?.Code;

    /// <summary>
    /// The type codes of every comprehension-required attribute Keryx did not recognise; a
    /// responder must answer 420 Unknown Attribute when this is non-empty
    /// (RFC 5389 section 7.3).
    /// </summary>
    public IReadOnlyList<ushort> UnknownComprehensionRequiredTypes
    {
        get
        {
            List<ushort>? types = null;
            foreach (var attribute in Attributes)
            {
                if (attribute is StunRawAttribute && attribute.IsComprehensionRequired)
                {
                    (types ??= []).Add((ushort)attribute.Type);
                }
            }

            return types ?? (IReadOnlyList<ushort>)[];
        }
    }

    /// <summary>
    /// Encodes the message, optionally appending MESSAGE-INTEGRITY and FINGERPRINT.
    /// </summary>
    /// <param name="integrityKey">
    /// The HMAC-SHA1 key from <see cref="StunCredentials"/>, or null to omit MESSAGE-INTEGRITY.
    /// </param>
    /// <param name="appendFingerprint">True to append a FINGERPRINT attribute.</param>
    /// <returns>A new array holding the encoded message.</returns>
    public byte[] Encode(byte[]? integrityKey = null, bool appendFingerprint = false)
    {
        var capacity = 512;
        while (true)
        {
            var buffer = new byte[capacity];
            try
            {
                var length = EncodeTo(buffer, integrityKey, appendFingerprint);
                return buffer[..length];
            }
            catch (ByteBufferException) when (capacity < 1 << 17)
            {
                capacity *= 4;
            }
        }
    }

    /// <summary>
    /// Encodes the message into <paramref name="destination"/>.
    /// </summary>
    /// <param name="destination">The buffer to write into.</param>
    /// <param name="integrityKey">
    /// The HMAC-SHA1 key from <see cref="StunCredentials"/>, or null to omit MESSAGE-INTEGRITY.
    /// </param>
    /// <param name="appendFingerprint">True to append a FINGERPRINT attribute.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ByteBufferException"><paramref name="destination"/> is too small.</exception>
    public int EncodeTo(Span<byte> destination, byte[]? integrityKey = null, bool appendFingerprint = false)
    {
        // A heap array rather than a stackalloc: ByteWriter's span parameters are not declared
        // `scoped`, so a stack-allocated span cannot be passed to them.
        var transactionId = TransactionId.ToArray();

        var writer = new ByteWriter(destination);
        writer.WriteU16(MessageType);
        var lengthOffset = writer.Reserve(2);
        writer.WriteU32(MagicCookie);
        writer.WriteBytes(transactionId);

        foreach (var attribute in Attributes)
        {
            if (attribute.Type is StunAttributeType.MessageIntegrity or StunAttributeType.Fingerprint)
            {
                continue;
            }

            WriteAttribute(ref writer, attribute, transactionId);
        }

        if (integrityKey is not null)
        {
            // RFC 5389 section 15.4: the length field must already include the MESSAGE-INTEGRITY
            // attribute (24 bytes) while the HMAC over the preceding bytes is computed.
            PatchLength(ref writer, lengthOffset, writer.Position - HeaderLength + MessageIntegrityAttributeLength);
            var digest = HMACSHA1.HashData(integrityKey, writer.Written);
            writer.WriteU16(MessageIntegrityCode);
            writer.WriteU16(StunMessageIntegrityAttribute.DigestLength);
            writer.WriteBytes(digest);
        }

        if (appendFingerprint)
        {
            // RFC 5389 section 15.5: same dummy-length rule, with the 8-byte FINGERPRINT attribute.
            PatchLength(ref writer, lengthOffset, writer.Position - HeaderLength + FingerprintAttributeLength);
            var crc = Crc32.Compute(writer.Written) ^ StunFingerprintAttribute.XorConstant;
            writer.WriteU16(FingerprintCode);
            writer.WriteU16(4);
            writer.WriteU32(crc);
        }

        PatchLength(ref writer, lengthOffset, writer.Position - HeaderLength);
        var written = writer.Position;
        _raw = destination[..written].ToArray();
        return written;
    }

    /// <summary>
    /// Decodes a STUN message from <paramref name="data"/>.
    /// </summary>
    /// <param name="data">
    /// The received bytes. Trailing bytes beyond the declared length are ignored.
    /// </param>
    /// <returns>The decoded message.</returns>
    /// <exception cref="ByteBufferException">The buffer is truncated.</exception>
    /// <exception cref="StunFormatException">The buffer is not a structurally valid STUN message.</exception>
    public static StunMessage Decode(ReadOnlySpan<byte> data)
    {
        var reader = new ByteReader(data);
        var messageType = reader.ReadU16();
        if ((messageType & 0xC000) != 0)
        {
            throw new StunFormatException("The two most significant bits of a STUN message type must be zero.");
        }

        var length = reader.ReadU16();
        if ((length & 0x3) != 0)
        {
            throw new StunFormatException($"A STUN message length must be a multiple of 4; got {length}.");
        }

        if (reader.ReadU32() != MagicCookie)
        {
            throw new StunFormatException("Missing or incorrect STUN magic cookie at offset 4.");
        }

        var transactionIdBytes = reader.ReadBytes(StunTransactionId.Length);
        var transactionId = new StunTransactionId(transactionIdBytes);

        if (data.Length < HeaderLength + length)
        {
            throw new ByteBufferException(
                $"STUN header declares {length} body byte(s) but only {data.Length - HeaderLength} are present.");
        }

        var messageClass = (StunClass)(((messageType & 0x0100) >> 7) | ((messageType & 0x0010) >> 4));
        var method = (StunMethod)(ushort)((messageType & 0x000F) | ((messageType & 0x00E0) >> 1) | ((messageType & 0x3E00) >> 2));

        var message = new StunMessage(messageClass, method, transactionId);
        DecodeAttributes(data.Slice(HeaderLength, length), transactionIdBytes, message.Attributes);
        message._raw = data[..(HeaderLength + length)].ToArray();
        return message;
    }

    /// <summary>
    /// Decodes a STUN message, returning false instead of throwing when the bytes are truncated or
    /// malformed. This is the entry point for handling untrusted network input.
    /// </summary>
    /// <param name="data">The received bytes.</param>
    /// <param name="message">The decoded message on success.</param>
    /// <returns>True when <paramref name="data"/> held a valid STUN message.</returns>
    public static bool TryDecode(ReadOnlySpan<byte> data, [NotNullWhen(true)] out StunMessage? message)
    {
        try
        {
            message = Decode(data);
            return true;
        }
        catch (ByteBufferException)
        {
            message = null;
            return false;
        }
        catch (StunFormatException)
        {
            message = null;
            return false;
        }
    }

    /// <summary>
    /// The cheap demultiplexing test used before parsing: a datagram looks like STUN when its two
    /// most significant bits are zero, the magic cookie is at offset 4, and the declared length is
    /// a multiple of four that fits in the datagram (RFC 5389 sections 6 and 7.3, RFC 7983).
    /// </summary>
    /// <param name="data">The datagram to classify.</param>
    /// <returns>True when the datagram should be handed to <see cref="TryDecode"/>.</returns>
    public static bool LooksLikeStun(ReadOnlySpan<byte> data)
    {
        if (data.Length < HeaderLength)
        {
            return false;
        }

        if ((data[0] & 0xC0) != 0)
        {
            return false;
        }

        if (BinaryPrimitives.ReadUInt32BigEndian(data[4..]) != MagicCookie)
        {
            return false;
        }

        var length = BinaryPrimitives.ReadUInt16BigEndian(data[2..]);
        return (length & 0x3) == 0 && HeaderLength + length <= data.Length;
    }

    /// <summary>
    /// Verifies this message's MESSAGE-INTEGRITY against <paramref name="key"/>, using the bytes in
    /// <see cref="Raw"/>.
    /// </summary>
    /// <param name="key">The HMAC-SHA1 key from <see cref="StunCredentials"/>.</param>
    /// <returns>False when the attribute is absent, malformed, or does not match.</returns>
    public bool ValidateMessageIntegrity(ReadOnlySpan<byte> key)
        => ValidateMessageIntegrity(Raw.Span, key);

    /// <summary>
    /// Verifies this message's MESSAGE-INTEGRITY against short-term credentials.
    /// </summary>
    /// <param name="password">The peer's password (the ICE pwd for connectivity checks).</param>
    /// <returns>False when the attribute is absent, malformed, or does not match.</returns>
    public bool ValidateMessageIntegrity(string password)
        => ValidateMessageIntegrity(Raw.Span, StunCredentials.ShortTermKey(password));

    /// <summary>Verifies this message's FINGERPRINT, using the bytes in <see cref="Raw"/>.</summary>
    /// <returns>False when the attribute is absent, not last, or does not match.</returns>
    public bool ValidateFingerprint() => ValidateFingerprint(Raw.Span);

    /// <summary>
    /// Verifies the MESSAGE-INTEGRITY attribute of an encoded message, re-applying the
    /// dummy-length rule of RFC 5389 section 15.4.
    /// </summary>
    /// <param name="message">The encoded message, exactly as received.</param>
    /// <param name="key">The HMAC-SHA1 key from <see cref="StunCredentials"/>.</param>
    /// <returns>False when the attribute is absent, malformed, or does not match.</returns>
    public static bool ValidateMessageIntegrity(ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
    {
        if (!TryFindAttribute(message, MessageIntegrityCode, out var offset, out var valueLength, out var total)
            || valueLength != StunMessageIntegrityAttribute.DigestLength
            || offset + MessageIntegrityAttributeLength > total)
        {
            return false;
        }

        var prefix = message[..offset].ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(
            prefix.AsSpan(2), (ushort)(offset + MessageIntegrityAttributeLength - HeaderLength));
        var expected = HMACSHA1.HashData(key, prefix);
        return CryptographicOperations.FixedTimeEquals(
            expected, message.Slice(offset + 4, StunMessageIntegrityAttribute.DigestLength));
    }

    /// <summary>
    /// Verifies the FINGERPRINT attribute of an encoded message, re-applying the dummy-length rule
    /// of RFC 5389 section 15.5.
    /// </summary>
    /// <param name="message">The encoded message, exactly as received.</param>
    /// <returns>False when the attribute is absent, not last, or does not match.</returns>
    public static bool ValidateFingerprint(ReadOnlySpan<byte> message)
    {
        if (!TryFindAttribute(message, FingerprintCode, out var offset, out var valueLength, out var total)
            || valueLength != 4
            || offset + FingerprintAttributeLength != total)
        {
            return false;
        }

        var prefix = message[..offset].ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(
            prefix.AsSpan(2), (ushort)(offset + FingerprintAttributeLength - HeaderLength));
        var expected = Crc32.Compute(prefix) ^ StunFingerprintAttribute.XorConstant;
        return expected == BinaryPrimitives.ReadUInt32BigEndian(message[(offset + 4)..]);
    }

    /// <summary>Encodes a class and method into the 16-bit wire message type (RFC 5389 section 6).</summary>
    /// <param name="messageClass">The message class.</param>
    /// <param name="method">The message method.</param>
    public static ushort EncodeMessageType(StunClass messageClass, StunMethod method)
    {
        var m = (uint)method;
        var c = (uint)messageClass;
        return (ushort)(((m & 0x0F80) << 2) | ((m & 0x0070) << 1) | (m & 0x000F)
                        | ((c & 0b10) << 7) | ((c & 0b01) << 4));
    }

    /// <inheritdoc />
    public override string ToString()
        => $"{Method} {Class} txid={TransactionId} attrs={Attributes.Count}";

    private static void PatchLength(ref ByteWriter writer, int lengthOffset, int value)
        => BinaryPrimitives.WriteUInt16BigEndian(writer.Patch(lengthOffset, 2), checked((ushort)value));

    private static void WriteAttribute(ref ByteWriter writer, StunAttribute attribute, ReadOnlySpan<byte> transactionId)
    {
        writer.WriteU16((ushort)attribute.Type);
        var lengthOffset = writer.Reserve(2);
        var start = writer.Position;
        attribute.WriteValue(ref writer, transactionId);
        var valueLength = writer.Position - start;
        BinaryPrimitives.WriteUInt16BigEndian(writer.Patch(lengthOffset, 2), checked((ushort)valueLength));
        writer.WriteZero(PaddingFor(valueLength));
    }

    private static void DecodeAttributes(ReadOnlySpan<byte> body, ReadOnlySpan<byte> transactionId, List<StunAttribute> into)
    {
        var reader = new ByteReader(body);
        while (reader.Remaining > 0)
        {
            var type = reader.ReadU16();
            var length = reader.ReadU16();
            var value = reader.ReadBytes(length);
            reader.Skip(PaddingFor(length));
            into.Add(DecodeAttribute(type, value, transactionId));
        }
    }

    private static StunAttribute DecodeAttribute(ushort type, ReadOnlySpan<byte> value, ReadOnlySpan<byte> transactionId)
        => (StunAttributeType)type switch
        {
            StunAttributeType.MappedAddress =>
                new StunMappedAddressAttribute(StunAddressAttribute.ReadValue(value, xored: false, transactionId)),
            StunAttributeType.XorMappedAddress =>
                new StunXorMappedAddressAttribute(StunAddressAttribute.ReadValue(value, xored: true, transactionId)),
            StunAttributeType.AlternateServer =>
                new StunAlternateServerAttribute(StunAddressAttribute.ReadValue(value, xored: false, transactionId)),
            StunAttributeType.Username => new StunUsernameAttribute(System.Text.Encoding.UTF8.GetString(value)),
            StunAttributeType.Realm => new StunRealmAttribute(System.Text.Encoding.UTF8.GetString(value)),
            StunAttributeType.Nonce => new StunNonceAttribute(System.Text.Encoding.UTF8.GetString(value)),
            StunAttributeType.Software => new StunSoftwareAttribute(System.Text.Encoding.UTF8.GetString(value)),
            StunAttributeType.MessageIntegrity => new StunMessageIntegrityAttribute(value),
            StunAttributeType.Fingerprint => new StunFingerprintAttribute(ReadU32(value)),
            StunAttributeType.ErrorCode => StunErrorCodeAttribute.ReadValue(value),
            StunAttributeType.UnknownAttributes => StunUnknownAttributesAttribute.ReadValue(value),
            StunAttributeType.Priority => new StunPriorityAttribute(ReadU32(value)),
            StunAttributeType.UseCandidate => new StunUseCandidateAttribute(),
            StunAttributeType.IceControlled => new StunIceControlledAttribute(ReadU64(value)),
            StunAttributeType.IceControlling => new StunIceControllingAttribute(ReadU64(value)),
            _ => new StunRawAttribute((StunAttributeType)type, value),
        };

    private static uint ReadU32(ReadOnlySpan<byte> value)
    {
        var reader = new ByteReader(value);
        return reader.ReadU32();
    }

    private static ulong ReadU64(ReadOnlySpan<byte> value)
    {
        var reader = new ByteReader(value);
        return reader.ReadU64();
    }

    private static int PaddingFor(int valueLength) => (4 - (valueLength & 3)) & 3;

    private static bool TryFindAttribute(
        ReadOnlySpan<byte> message, ushort wanted, out int offset, out int valueLength, out int total)
    {
        offset = 0;
        valueLength = 0;
        total = 0;

        if (!LooksLikeStun(message))
        {
            return false;
        }

        total = HeaderLength + BinaryPrimitives.ReadUInt16BigEndian(message[2..]);
        var position = HeaderLength;
        while (position + 4 <= total)
        {
            var type = BinaryPrimitives.ReadUInt16BigEndian(message[position..]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(message[(position + 2)..]);
            if (type == wanted)
            {
                offset = position;
                valueLength = length;
                return true;
            }

            position += 4 + length + PaddingFor(length);
        }

        return false;
    }
}
