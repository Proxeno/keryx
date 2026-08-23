using Keryx.Core;

namespace Keryx.Stun;

/// <summary>PRIORITY: the priority the sender would assign to a peer-reflexive candidate learned from this check (RFC 8445 section 16.1).</summary>
public sealed class StunPriorityAttribute : StunAttribute
{
    /// <summary>Creates the attribute.</summary>
    /// <param name="priority">The candidate priority.</param>
    public StunPriorityAttribute(uint priority) => Priority = priority;

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.Priority;

    /// <summary>The candidate priority.</summary>
    public uint Priority { get; }

    internal override void WriteValue(ref ByteWriter writer, ReadOnlySpan<byte> transactionId)
        => writer.WriteU32(Priority);
}

/// <summary>USE-CANDIDATE: a zero-length flag by which a controlling agent nominates a pair (RFC 8445 section 16.1).</summary>
public sealed class StunUseCandidateAttribute : StunAttribute
{
    /// <summary>The shared instance; the attribute has no value.</summary>
    public static StunUseCandidateAttribute Instance { get; } = new();

    /// <summary>Creates the attribute.</summary>
    public StunUseCandidateAttribute()
    {
    }

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.UseCandidate;

    internal override void WriteValue(ref ByteWriter writer, ReadOnlySpan<byte> transactionId)
    {
    }
}

/// <summary>
/// Base class for the 64-bit tie-breaker attributes that declare an ICE agent's role
/// (RFC 8445 section 16.1).
/// </summary>
public abstract class StunIceRoleAttribute : StunAttribute
{
    private protected StunIceRoleAttribute(ulong tieBreaker) => TieBreaker = tieBreaker;

    /// <summary>The sender's random tie-breaker, compared to resolve role conflicts.</summary>
    public ulong TieBreaker { get; }

    internal override void WriteValue(ref ByteWriter writer, ReadOnlySpan<byte> transactionId)
        => writer.WriteU64(TieBreaker);
}

/// <summary>ICE-CONTROLLED: the sender believes it is in the controlled role (RFC 8445 section 16.1).</summary>
public sealed class StunIceControlledAttribute : StunIceRoleAttribute
{
    /// <summary>Creates the attribute.</summary>
    /// <param name="tieBreaker">The sender's tie-breaker value.</param>
    public StunIceControlledAttribute(ulong tieBreaker)
        : base(tieBreaker)
    {
    }

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.IceControlled;
}

/// <summary>ICE-CONTROLLING: the sender believes it is in the controlling role (RFC 8445 section 16.1).</summary>
public sealed class StunIceControllingAttribute : StunIceRoleAttribute
{
    /// <summary>Creates the attribute.</summary>
    /// <param name="tieBreaker">The sender's tie-breaker value.</param>
    public StunIceControllingAttribute(ulong tieBreaker)
        : base(tieBreaker)
    {
    }

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.IceControlling;
}

/// <summary>
/// MESSAGE-INTEGRITY: an HMAC-SHA1 over the message up to and including this attribute's header
/// (RFC 5389 section 15.4).
/// </summary>
/// <remarks>
/// Instances of this type appear on decoded messages so callers can inspect the received digest.
/// When encoding, the digest is computed by
/// <see cref="StunMessage.Encode(byte[], bool, bool)"/> from the supplied key; any instance present in
/// <see cref="StunMessage.Attributes"/> is ignored.
/// </remarks>
public sealed class StunMessageIntegrityAttribute : StunAttribute
{
    /// <summary>Length of the HMAC-SHA1 digest in bytes.</summary>
    public const int DigestLength = 20;

    /// <summary>Creates the attribute from a 20-byte digest.</summary>
    /// <param name="digest">The HMAC-SHA1 digest. Copied.</param>
    public StunMessageIntegrityAttribute(ReadOnlySpan<byte> digest)
    {
        if (digest.Length != DigestLength)
        {
            throw new ByteBufferException($"A MESSAGE-INTEGRITY digest is {DigestLength} bytes; got {digest.Length}.");
        }

        Digest = digest.ToArray();
    }

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.MessageIntegrity;

    /// <summary>The 20-byte HMAC-SHA1 digest.</summary>
    public byte[] Digest { get; }

    internal override void WriteValue(ref ByteWriter writer, ReadOnlySpan<byte> transactionId)
        => writer.WriteBytes(Digest);
}

/// <summary>
/// FINGERPRINT: CRC-32 of the message up to but not including this attribute, XORed with
/// 0x5354554e (RFC 5389 section 15.5).
/// </summary>
/// <remarks>
/// When encoding, the value is computed by <see cref="StunMessage.Encode(byte[], bool, bool)"/>; any
/// instance present in <see cref="StunMessage.Attributes"/> is ignored.
/// </remarks>
public sealed class StunFingerprintAttribute : StunAttribute
{
    /// <summary>The constant the CRC-32 is XORed with, chosen so a STUN message is distinguishable from other protocols.</summary>
    public const uint XorConstant = 0x5354554Eu;

    /// <summary>Creates the attribute from an already-XORed value.</summary>
    /// <param name="value">The value as it appears on the wire.</param>
    public StunFingerprintAttribute(uint value) => Value = value;

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.Fingerprint;

    /// <summary>The value as it appears on the wire (CRC-32 already XORed with <see cref="XorConstant"/>).</summary>
    public uint Value { get; }

    internal override void WriteValue(ref ByteWriter writer, ReadOnlySpan<byte> transactionId)
        => writer.WriteU32(Value);
}
