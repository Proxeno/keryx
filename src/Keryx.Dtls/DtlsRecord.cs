using Keryx.Core;

namespace Keryx.Dtls;

/// <summary>
/// A parsed DTLS record header (RFC 6347 §4.1) plus a slice referencing the record body inside the
/// datagram it arrived in.
/// </summary>
internal readonly ref struct DtlsRecord
{
    public DtlsRecord(ContentType type, ushort version, ushort epoch, ulong sequenceNumber, ReadOnlySpan<byte> fragment)
    {
        Type = type;
        Version = version;
        Epoch = epoch;
        SequenceNumber = sequenceNumber;
        Fragment = fragment;
    }

    public ContentType Type { get; }

    public ushort Version { get; }

    public ushort Epoch { get; }

    public ulong SequenceNumber { get; }

    public ReadOnlySpan<byte> Fragment { get; }
}

/// <summary>
/// Cursor over the (possibly multiple) DTLS records packed into a single datagram, per RFC 6347
/// §4.1.1. Parsing never throws: a truncated or nonsensical header simply ends the enumeration,
/// which is the "discard the record" behaviour required by RFC 6347 §4.1.2.7.
/// </summary>
internal ref struct DtlsRecordReader
{
    private readonly ReadOnlySpan<byte> _datagram;
    private int _offset;

    public DtlsRecordReader(ReadOnlySpan<byte> datagram)
    {
        _datagram = datagram;
        _offset = 0;
    }

    /// <summary>
    /// True when a well-formed record was read into <paramref name="record"/>. False ends the
    /// datagram — either cleanly, or because the remainder is unparseable and must be dropped.
    /// </summary>
    public bool TryReadNext(out DtlsRecord record)
    {
        record = default;
        if (_datagram.Length - _offset < DtlsLimits.RecordHeaderLength)
        {
            return false;
        }

        var header = _datagram.Slice(_offset, DtlsLimits.RecordHeaderLength);
        var reader = new ByteReader(header);
        var type = (ContentType)reader.ReadU8();
        var version = reader.ReadU16();
        var epoch = reader.ReadU16();
        var sequence = reader.ReadU48();
        var length = reader.ReadU16();

        var bodyStart = _offset + DtlsLimits.RecordHeaderLength;
        if (_datagram.Length - bodyStart < length)
        {
            // Truncated record: the rest of the datagram is unusable.
            _offset = _datagram.Length;
            return false;
        }

        record = new DtlsRecord(type, version, epoch, sequence, _datagram.Slice(bodyStart, length));
        _offset = bodyStart + length;
        return true;
    }
}

internal static class DtlsRecordWriter
{
    /// <summary>Writes just the 13-byte record header for a body of <paramref name="bodyLength"/> bytes.</summary>
    public static void WriteHeader(
        Span<byte> destination,
        ContentType type,
        ushort version,
        ushort epoch,
        ulong sequenceNumber,
        int bodyLength)
    {
        var writer = new ByteWriter(destination);
        writer.WriteU8((byte)type);
        writer.WriteU16(version);
        writer.WriteU16(epoch);
        writer.WriteU48(sequenceNumber);
        writer.WriteU16(checked((ushort)bodyLength));
    }

    /// <summary>Writes a record header followed by <paramref name="fragment"/>.</summary>
    public static int Write(
        Span<byte> destination,
        ContentType type,
        ushort version,
        ushort epoch,
        ulong sequenceNumber,
        ReadOnlySpan<byte> fragment)
    {
        var writer = new ByteWriter(destination);
        writer.WriteU8((byte)type);
        writer.WriteU16(version);
        writer.WriteU16(epoch);
        writer.WriteU48(sequenceNumber);
        writer.WriteU16(checked((ushort)fragment.Length));
        writer.WriteBytes(fragment);
        return writer.Position;
    }
}
