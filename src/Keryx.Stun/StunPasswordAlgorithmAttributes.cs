using System.Security.Cryptography;
using Keryx.Core;

namespace Keryx.Stun;

/// <summary>
/// One algorithm entry as carried inside PASSWORD-ALGORITHM or PASSWORD-ALGORITHMS: an
/// IANA-registered algorithm code together with its algorithm-specific parameters
/// (RFC 8489 sections 14.11-14.12 and 18.5.1). Both algorithms Keryx implements, MD5 and SHA-256,
/// take no parameters; an unrecognised algorithm from the wire is preserved with whatever
/// parameters it carried so it can be echoed back unchanged.
/// </summary>
public sealed class StunPasswordAlgorithmEntry
{
    /// <summary>Creates an entry from a well-known algorithm with no parameters.</summary>
    /// <param name="algorithm">The password algorithm.</param>
    public StunPasswordAlgorithmEntry(StunPasswordAlgorithm algorithm)
        : this((ushort)algorithm, [])
    {
    }

    /// <summary>Creates an entry.</summary>
    /// <param name="algorithm">The algorithm code.</param>
    /// <param name="parameters">The algorithm-specific parameters; stored by reference, not copied.</param>
    public StunPasswordAlgorithmEntry(ushort algorithm, byte[] parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        Algorithm = algorithm;
        Parameters = parameters;
    }

    /// <summary>The algorithm code, from the IANA STUN Password Algorithms registry.</summary>
    public ushort Algorithm { get; }

    /// <summary>The algorithm-specific parameters, excluding the four-byte header and any padding.</summary>
    public byte[] Parameters { get; }

    /// <summary>Encoded length in bytes excluding trailing padding.</summary>
    public int Length => 4 + Parameters.Length;

    /// <summary>Encoded length rounded up to the next four-byte boundary.</summary>
    public int PaddedLength => (Length + 3) & ~3;

    /// <summary>Writes the entry, including alignment padding, to <paramref name="writer"/>.</summary>
    /// <param name="writer">Destination writer.</param>
    public void WriteTo(ref ByteWriter writer)
    {
        writer.WriteU16(Algorithm);
        writer.WriteU16((ushort)Parameters.Length);
        writer.WriteBytes(Parameters);
        writer.WriteZero(PaddedLength - Length);
    }

    /// <summary>Parses a sequence of entries that fills <paramref name="body"/>.</summary>
    /// <param name="body">Buffer holding zero or more consecutive entries.</param>
    /// <returns>The parsed entries in wire order.</returns>
    public static List<StunPasswordAlgorithmEntry> ParseAll(ReadOnlySpan<byte> body)
    {
        var result = new List<StunPasswordAlgorithmEntry>();
        var reader = new ByteReader(body);
        while (reader.Remaining >= 4)
        {
            var algorithm = reader.ReadU16();
            var length = reader.ReadU16();
            var parameters = reader.ReadBytes(length).ToArray();
            var padding = (4 - (length & 3)) & 3;
            reader.Skip(Math.Min(padding, reader.Remaining));
            result.Add(new StunPasswordAlgorithmEntry(algorithm, parameters));
        }

        return result;
    }
}

/// <summary>
/// PASSWORD-ALGORITHM: the single RFC 8489 password algorithm a request was, or a subsequent
/// request will be, keyed with (RFC 8489 section 14.12). Comprehension-required.
/// </summary>
public sealed class StunPasswordAlgorithmAttribute : StunAttribute
{
    /// <summary>Creates the attribute for a well-known algorithm with no parameters.</summary>
    /// <param name="algorithm">The negotiated password algorithm.</param>
    public StunPasswordAlgorithmAttribute(StunPasswordAlgorithm algorithm)
        : this(new StunPasswordAlgorithmEntry(algorithm))
    {
    }

    /// <summary>Creates the attribute from an already-parsed entry.</summary>
    /// <param name="entry">The algorithm and its parameters.</param>
    public StunPasswordAlgorithmAttribute(StunPasswordAlgorithmEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        Entry = entry;
    }

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.PasswordAlgorithm;

    /// <summary>The algorithm code, from the IANA STUN Password Algorithms registry.</summary>
    public ushort Algorithm => Entry.Algorithm;

    /// <summary>The algorithm-specific parameters; empty for MD5 and SHA-256.</summary>
    public byte[] Parameters => Entry.Parameters;

    /// <summary>The underlying entry.</summary>
    public StunPasswordAlgorithmEntry Entry { get; }

    internal override void WriteValue(ref ByteWriter writer, ReadOnlySpan<byte> transactionId)
        => Entry.WriteTo(ref writer);

    internal static StunPasswordAlgorithmAttribute ReadValue(ReadOnlySpan<byte> value)
    {
        var entries = StunPasswordAlgorithmEntry.ParseAll(value);
        if (entries.Count == 0)
        {
            throw new StunFormatException("A PASSWORD-ALGORITHM attribute must carry exactly one algorithm entry; got none.");
        }

        return new StunPasswordAlgorithmAttribute(entries[0]);
    }
}

/// <summary>
/// PASSWORD-ALGORITHMS: the password algorithms a server supports, in preferential order
/// (RFC 8489 section 14.11). Comprehension-optional. A client answering a challenge that carries
/// this attribute must echo it back unmodified alongside the PASSWORD-ALGORITHM it picked, so the
/// server can detect an on-path attacker having stripped an entry to bid the client down to a
/// weaker algorithm (RFC 8489 section 9.2.1).
/// </summary>
public sealed class StunPasswordAlgorithmsAttribute : StunAttribute
{
    /// <summary>Creates the attribute.</summary>
    /// <param name="entries">The offered algorithms, in preferential order.</param>
    public StunPasswordAlgorithmsAttribute(IEnumerable<StunPasswordAlgorithmEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        Entries = [.. entries];
    }

    /// <summary>Creates the attribute from well-known algorithms with no parameters.</summary>
    /// <param name="algorithms">The offered algorithms, in preferential order.</param>
    public static StunPasswordAlgorithmsAttribute Offering(params ReadOnlySpan<StunPasswordAlgorithm> algorithms)
        => new(algorithms.ToArray().Select(a => new StunPasswordAlgorithmEntry(a)));

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.PasswordAlgorithms;

    /// <summary>The offered algorithm entries, in preferential order.</summary>
    public IReadOnlyList<StunPasswordAlgorithmEntry> Entries { get; }

    /// <summary>The offered algorithm codes, in preferential order.</summary>
    public IEnumerable<ushort> Algorithms => Entries.Select(e => e.Algorithm);

    /// <summary>True when <paramref name="algorithm"/> appears among the offered entries.</summary>
    /// <param name="algorithm">The algorithm to look for.</param>
    public bool Supports(StunPasswordAlgorithm algorithm) => Algorithms.Contains((ushort)algorithm);

    internal override void WriteValue(ref ByteWriter writer, ReadOnlySpan<byte> transactionId)
    {
        foreach (var entry in Entries)
        {
            entry.WriteTo(ref writer);
        }
    }

    internal static StunPasswordAlgorithmsAttribute ReadValue(ReadOnlySpan<byte> value)
        => new(StunPasswordAlgorithmEntry.ParseAll(value));
}

/// <summary>
/// MESSAGE-INTEGRITY-SHA256: an HMAC-SHA256 over the message up to and including this attribute's
/// header, keyed the same way as MESSAGE-INTEGRITY but used once RFC 8489 password-algorithm
/// negotiation has taken place (RFC 8489 section 14.6).
/// </summary>
/// <remarks>
/// Instances of this type appear on decoded messages so callers can inspect the received digest.
/// When encoding, the digest is computed by
/// <see cref="StunMessage.Encode(byte[], bool, bool)"/> from the supplied key; any instance present
/// in <see cref="StunMessage.Attributes"/> is ignored. RFC 8489 allows the value to be truncated to
/// as few as 16 bytes; Keryx always emits and requires the full 32-byte HMAC-SHA256 output, which
/// is what every long-term-credential TURN deployment Keryx has been tested against sends.
/// </remarks>
public sealed class StunMessageIntegritySha256Attribute : StunAttribute
{
    /// <summary>Length of the HMAC-SHA256 digest in bytes, as Keryx always emits and requires it.</summary>
    public const int DigestLength = 32;

    /// <summary>Creates the attribute from a 32-byte digest.</summary>
    /// <param name="digest">The HMAC-SHA256 digest. Copied.</param>
    public StunMessageIntegritySha256Attribute(ReadOnlySpan<byte> digest)
    {
        if (digest.Length != DigestLength)
        {
            throw new ByteBufferException($"Keryx requires a {DigestLength}-byte MESSAGE-INTEGRITY-SHA256 digest; got {digest.Length}.");
        }

        Digest = digest.ToArray();
    }

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.MessageIntegritySha256;

    /// <summary>The 32-byte HMAC-SHA256 digest.</summary>
    public byte[] Digest { get; }

    internal override void WriteValue(ref ByteWriter writer, ReadOnlySpan<byte> transactionId)
        => writer.WriteBytes(Digest);

    internal static byte[] ComputeDigest(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message)
        => HMACSHA256.HashData(key, message);
}
