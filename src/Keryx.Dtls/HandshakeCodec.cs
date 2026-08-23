using Keryx.Core;

namespace Keryx.Dtls;

/// <summary>Parsed ClientHello (RFC 5246 §7.4.1.2 with the DTLS cookie field from RFC 6347 §4.2.1).</summary>
internal sealed class ClientHelloMessage
{
    public ushort Version { get; init; }

    public byte[] Random { get; init; } = [];

    public byte[] SessionId { get; init; } = [];

    public byte[] Cookie { get; init; } = [];

    public ushort[] CipherSuites { get; init; } = [];

    public byte[] CompressionMethods { get; init; } = [];

    public List<ushort> SupportedGroups { get; } = [];

    public List<SigHashAlgorithm> SignatureAlgorithms { get; } = [];

    public List<ushort> SrtpProfiles { get; } = [];

    public bool ExtendedMasterSecret { get; set; }

    public bool RenegotiationInfo { get; set; }

    public bool EcPointFormats { get; set; }
}

/// <summary>Parsed ServerHello.</summary>
internal sealed class ServerHelloMessage
{
    public ushort Version { get; init; }

    public byte[] Random { get; init; } = [];

    public byte[] SessionId { get; init; } = [];

    public ushort CipherSuite { get; init; }

    public byte CompressionMethod { get; init; }

    public bool ExtendedMasterSecret { get; set; }

    public ushort? SrtpProfile { get; set; }
}

/// <summary>Parsed ServerKeyExchange for an ECDHE key exchange (RFC 8422 §5.4).</summary>
internal sealed class ServerKeyExchangeMessage
{
    public byte CurveType { get; init; }

    public ushort NamedCurve { get; init; }

    public byte[] PublicPoint { get; init; } = [];

    public SigHashAlgorithm Algorithm { get; init; }

    public byte[] Signature { get; init; } = [];

    /// <summary>The signed portion: <c>curve_type || named_curve || ECPoint</c>.</summary>
    public byte[] SignedParams { get; init; } = [];
}

/// <summary>Parsed CertificateRequest.</summary>
internal sealed class CertificateRequestMessage
{
    public byte[] CertificateTypes { get; init; } = [];

    public List<SigHashAlgorithm> SignatureAlgorithms { get; } = [];
}

/// <summary>Serialisation and parsing of DTLS 1.2 handshake message bodies.</summary>
internal static class HandshakeCodec
{
    private const int BuildBufferSize = 64 * 1024;

    public static ClientHelloMessage ParseClientHello(ReadOnlySpan<byte> body)
    {
        var reader = new ByteReader(body);
        var version = reader.ReadU16();
        var random = reader.ReadBytes(32).ToArray();
        var sessionId = reader.ReadBytes(reader.ReadU8()).ToArray();
        var cookie = reader.ReadBytes(reader.ReadU8()).ToArray();

        var suitesLength = reader.ReadU16();
        if ((suitesLength & 1) != 0)
        {
            throw new DtlsException("ClientHello cipher_suites has an odd byte length.", DtlsAlertDescription.DecodeError);
        }

        var suites = new ushort[suitesLength / 2];
        for (var i = 0; i < suites.Length; i++)
        {
            suites[i] = reader.ReadU16();
        }

        var compression = reader.ReadBytes(reader.ReadU8()).ToArray();

        var hello = new ClientHelloMessage
        {
            Version = version,
            Random = random,
            SessionId = sessionId,
            Cookie = cookie,
            CipherSuites = suites,
            CompressionMethods = compression,
        };

        // The renegotiation SCSV is equivalent to an empty renegotiation_info extension (RFC 5746).
        if (Array.IndexOf(suites, CipherSuites.EmptyRenegotiationInfoScsv) >= 0)
        {
            hello.RenegotiationInfo = true;
        }

        if (reader.Remaining >= 2)
        {
            var extensionsLength = reader.ReadU16();
            var extensions = reader.ReadBytes(extensionsLength);
            ParseClientExtensions(hello, extensions);
        }

        return hello;
    }

    public static ServerHelloMessage ParseServerHello(ReadOnlySpan<byte> body)
    {
        var reader = new ByteReader(body);
        var version = reader.ReadU16();
        var random = reader.ReadBytes(32).ToArray();
        var sessionId = reader.ReadBytes(reader.ReadU8()).ToArray();
        var suite = reader.ReadU16();
        var compression = reader.ReadU8();

        var hello = new ServerHelloMessage
        {
            Version = version,
            Random = random,
            SessionId = sessionId,
            CipherSuite = suite,
            CompressionMethod = compression,
        };

        if (reader.Remaining >= 2)
        {
            var extensionsLength = reader.ReadU16();
            var extensions = reader.ReadBytes(extensionsLength);
            var extReader = new ByteReader(extensions);
            while (extReader.Remaining >= 4)
            {
                var type = extReader.ReadU16();
                var length = extReader.ReadU16();
                var data = extReader.ReadBytes(length);
                switch (type)
                {
                    case ExtensionTypes.ExtendedMasterSecret:
                        hello.ExtendedMasterSecret = true;
                        break;
                    case ExtensionTypes.UseSrtp:
                        var srtpReader = new ByteReader(data);
                        var profilesLength = srtpReader.ReadU16();
                        if (profilesLength >= 2)
                        {
                            hello.SrtpProfile = srtpReader.ReadU16();
                        }

                        break;
                    default:
                        break;
                }
            }
        }

        return hello;
    }

    public static byte[] ParseHelloVerifyRequestCookie(ReadOnlySpan<byte> body)
    {
        var reader = new ByteReader(body);
        _ = reader.ReadU16();
        return reader.ReadBytes(reader.ReadU8()).ToArray();
    }

    /// <summary>Parses a Certificate message into its DER-encoded certificate chain, leaf first.</summary>
    public static List<byte[]> ParseCertificate(ReadOnlySpan<byte> body)
    {
        var result = new List<byte[]>();
        var reader = new ByteReader(body);
        var listLength = (int)reader.ReadU24();
        var list = reader.ReadBytes(listLength);
        var listReader = new ByteReader(list);
        while (listReader.Remaining > 0)
        {
            var certLength = (int)listReader.ReadU24();
            result.Add(listReader.ReadBytes(certLength).ToArray());
        }

        return result;
    }

    public static ServerKeyExchangeMessage ParseServerKeyExchange(ReadOnlySpan<byte> body)
    {
        var reader = new ByteReader(body);
        var curveType = reader.ReadU8();
        if (curveType != EcCurveTypes.NamedCurve)
        {
            throw new DtlsException(
                $"Unsupported ServerKeyExchange curve type {curveType}; only named_curve is supported.",
                DtlsAlertDescription.HandshakeFailure);
        }

        var namedCurve = reader.ReadU16();
        var pointLength = reader.ReadU8();
        var point = reader.ReadBytes(pointLength).ToArray();
        var signedLength = reader.Position;
        var signedParams = body[..signedLength].ToArray();

        var hash = reader.ReadU8();
        var signature = reader.ReadU8();
        var sigLength = reader.ReadU16();
        var sig = reader.ReadBytes(sigLength).ToArray();

        return new ServerKeyExchangeMessage
        {
            CurveType = curveType,
            NamedCurve = namedCurve,
            PublicPoint = point,
            Algorithm = new SigHashAlgorithm(hash, signature),
            Signature = sig,
            SignedParams = signedParams,
        };
    }

    public static CertificateRequestMessage ParseCertificateRequest(ReadOnlySpan<byte> body)
    {
        var reader = new ByteReader(body);
        var typesLength = reader.ReadU8();
        var request = new CertificateRequestMessage
        {
            CertificateTypes = reader.ReadBytes(typesLength).ToArray(),
        };

        var sigAlgsLength = reader.ReadU16();
        var sigAlgs = reader.ReadBytes(sigAlgsLength);
        var sigReader = new ByteReader(sigAlgs);
        while (sigReader.Remaining >= 2)
        {
            request.SignatureAlgorithms.Add(new SigHashAlgorithm(sigReader.ReadU8(), sigReader.ReadU8()));
        }

        // certificate_authorities is present but ignored: WebRTC peers are self-signed.
        return request;
    }

    public static (SigHashAlgorithm Algorithm, byte[] Signature) ParseCertificateVerify(ReadOnlySpan<byte> body)
    {
        var reader = new ByteReader(body);
        var hash = reader.ReadU8();
        var signature = reader.ReadU8();
        var length = reader.ReadU16();
        return (new SigHashAlgorithm(hash, signature), reader.ReadBytes(length).ToArray());
    }

    public static byte[] ParseClientKeyExchange(ReadOnlySpan<byte> body)
    {
        var reader = new ByteReader(body);
        var length = reader.ReadU8();
        return reader.ReadBytes(length).ToArray();
    }

    public static byte[] BuildClientHello(
        ReadOnlySpan<byte> random,
        ReadOnlySpan<byte> cookie,
        IReadOnlyList<ushort> cipherSuites,
        IReadOnlyList<ushort> namedGroups,
        IReadOnlyList<SrtpProtectionProfile> srtpProfiles)
    {
        var buffer = new byte[BuildBufferSize];
        var writer = new ByteWriter(buffer);
        writer.WriteU16(ProtocolVersions.Dtls12);
        writer.WriteBytes(random);
        writer.WriteU8(0); // empty session_id — Keryx never resumes.
        writer.WriteU8((byte)cookie.Length);
        writer.WriteBytes(cookie);

        writer.WriteU16((ushort)(cipherSuites.Count * 2));
        foreach (var suite in cipherSuites)
        {
            writer.WriteU16(suite);
        }

        writer.WriteU8(1);
        writer.WriteU8(0); // null compression

        var extensionsLengthOffset = writer.Reserve(2);
        var extensionsStart = writer.Position;

        WriteSupportedGroups(ref writer, namedGroups);
        WriteEcPointFormats(ref writer);
        WriteSignatureAlgorithms(ref writer);
        WriteExtension(ref writer, ExtensionTypes.ExtendedMasterSecret, []);
        WriteExtension(ref writer, ExtensionTypes.RenegotiationInfo, [0x00]);
        WriteUseSrtp(ref writer, srtpProfiles);

        PatchLength16(ref writer, extensionsLengthOffset, writer.Position - extensionsStart);
        return writer.Written.ToArray();
    }

    public static byte[] BuildServerHello(
        ReadOnlySpan<byte> random,
        ushort cipherSuite,
        bool extendedMasterSecret,
        bool renegotiationInfo,
        bool ecPointFormats,
        SrtpProtectionProfile srtpProfile)
    {
        var buffer = new byte[1024];
        var writer = new ByteWriter(buffer);
        writer.WriteU16(ProtocolVersions.Dtls12);
        writer.WriteBytes(random);
        writer.WriteU8(0); // empty session_id
        writer.WriteU16(cipherSuite);
        writer.WriteU8(0); // null compression

        var extensionsLengthOffset = writer.Reserve(2);
        var extensionsStart = writer.Position;

        if (renegotiationInfo)
        {
            WriteExtension(ref writer, ExtensionTypes.RenegotiationInfo, [0x00]);
        }

        if (extendedMasterSecret)
        {
            WriteExtension(ref writer, ExtensionTypes.ExtendedMasterSecret, []);
        }

        if (ecPointFormats)
        {
            WriteEcPointFormats(ref writer);
        }

        if (srtpProfile != SrtpProtectionProfile.None)
        {
            WriteUseSrtp(ref writer, [srtpProfile]);
        }

        var extensionsLength = writer.Position - extensionsStart;
        if (extensionsLength == 0)
        {
            // No extensions: omit the length field entirely rather than sending a zero-length block.
            return writer.Written[..extensionsLengthOffset].ToArray();
        }

        PatchLength16(ref writer, extensionsLengthOffset, extensionsLength);
        return writer.Written.ToArray();
    }

    public static byte[] BuildCertificate(params ReadOnlySpan<byte[]> chain)
    {
        var total = 3;
        foreach (var cert in chain)
        {
            total += 3 + cert.Length;
        }

        var buffer = new byte[total];
        var writer = new ByteWriter(buffer);
        var listLength = 0;
        foreach (var cert in chain)
        {
            listLength += 3 + cert.Length;
        }

        writer.WriteU24((uint)listLength);
        foreach (var cert in chain)
        {
            writer.WriteU24((uint)cert.Length);
            writer.WriteBytes(cert);
        }

        return writer.Written.ToArray();
    }

    public static byte[] BuildServerKeyExchangeParams(ushort namedCurve, ReadOnlySpan<byte> publicPoint)
    {
        var buffer = new byte[4 + publicPoint.Length];
        var writer = new ByteWriter(buffer);
        writer.WriteU8(EcCurveTypes.NamedCurve);
        writer.WriteU16(namedCurve);
        writer.WriteU8((byte)publicPoint.Length);
        writer.WriteBytes(publicPoint);
        return writer.Written.ToArray();
    }

    public static byte[] BuildServerKeyExchange(
        ReadOnlySpan<byte> signedParams,
        SigHashAlgorithm algorithm,
        ReadOnlySpan<byte> signature)
    {
        var buffer = new byte[signedParams.Length + 4 + signature.Length];
        var writer = new ByteWriter(buffer);
        writer.WriteBytes(signedParams);
        writer.WriteU8(algorithm.Hash);
        writer.WriteU8(algorithm.Signature);
        writer.WriteU16((ushort)signature.Length);
        writer.WriteBytes(signature);
        return writer.Written.ToArray();
    }

    public static byte[] BuildCertificateRequest(IReadOnlyList<SigHashAlgorithm> algorithms)
    {
        var buffer = new byte[64 + (algorithms.Count * 2)];
        var writer = new ByteWriter(buffer);
        writer.WriteU8(2);
        writer.WriteU8(ClientCertificateTypes.EcdsaSign);
        writer.WriteU8(ClientCertificateTypes.RsaSign);
        writer.WriteU16((ushort)(algorithms.Count * 2));
        foreach (var algorithm in algorithms)
        {
            writer.WriteU8(algorithm.Hash);
            writer.WriteU8(algorithm.Signature);
        }

        writer.WriteU16(0); // no certificate_authorities
        return writer.Written.ToArray();
    }

    public static byte[] BuildCertificateVerify(SigHashAlgorithm algorithm, ReadOnlySpan<byte> signature)
    {
        var buffer = new byte[4 + signature.Length];
        var writer = new ByteWriter(buffer);
        writer.WriteU8(algorithm.Hash);
        writer.WriteU8(algorithm.Signature);
        writer.WriteU16((ushort)signature.Length);
        writer.WriteBytes(signature);
        return writer.Written.ToArray();
    }

    public static byte[] BuildClientKeyExchange(ReadOnlySpan<byte> publicPoint)
    {
        var buffer = new byte[1 + publicPoint.Length];
        var writer = new ByteWriter(buffer);
        writer.WriteU8((byte)publicPoint.Length);
        writer.WriteBytes(publicPoint);
        return writer.Written.ToArray();
    }

    private static void ParseClientExtensions(ClientHelloMessage hello, ReadOnlySpan<byte> extensions)
    {
        var reader = new ByteReader(extensions);
        while (reader.Remaining >= 4)
        {
            var type = reader.ReadU16();
            var length = reader.ReadU16();
            if (reader.Remaining < length)
            {
                throw new DtlsException("Truncated ClientHello extension.", DtlsAlertDescription.DecodeError);
            }

            var data = reader.ReadBytes(length);
            switch (type)
            {
                case ExtensionTypes.SupportedGroups:
                {
                    var groupReader = new ByteReader(data);
                    var listLength = groupReader.ReadU16();
                    var end = groupReader.Position + listLength;
                    while (groupReader.Position + 2 <= end && groupReader.Remaining >= 2)
                    {
                        hello.SupportedGroups.Add(groupReader.ReadU16());
                    }

                    break;
                }

                case ExtensionTypes.SignatureAlgorithms:
                {
                    var sigReader = new ByteReader(data);
                    var listLength = sigReader.ReadU16();
                    var end = sigReader.Position + listLength;
                    while (sigReader.Position + 2 <= end && sigReader.Remaining >= 2)
                    {
                        hello.SignatureAlgorithms.Add(new SigHashAlgorithm(sigReader.ReadU8(), sigReader.ReadU8()));
                    }

                    break;
                }

                case ExtensionTypes.UseSrtp:
                {
                    var srtpReader = new ByteReader(data);
                    var listLength = srtpReader.ReadU16();
                    var end = srtpReader.Position + listLength;
                    while (srtpReader.Position + 2 <= end && srtpReader.Remaining >= 2)
                    {
                        hello.SrtpProfiles.Add(srtpReader.ReadU16());
                    }

                    break;
                }

                case ExtensionTypes.ExtendedMasterSecret:
                    hello.ExtendedMasterSecret = true;
                    break;

                case ExtensionTypes.RenegotiationInfo:
                    hello.RenegotiationInfo = true;
                    break;

                case ExtensionTypes.EcPointFormats:
                    hello.EcPointFormats = true;
                    break;

                default:
                    // Unknown extensions are ignored (RFC 5246 §7.4.1.4).
                    break;
            }
        }
    }

    // The extension payloads are heap arrays rather than stackalloc spans so that ByteWriter's
    // (unscoped) WriteBytes parameter cannot trip ref-safety analysis.
    private static void WriteExtension(ref ByteWriter writer, ushort type, byte[] data)
    {
        writer.WriteU16(type);
        writer.WriteU16((ushort)data.Length);
        writer.WriteBytes(data);
    }

    private static void WriteSupportedGroups(ref ByteWriter writer, IReadOnlyList<ushort> groups)
    {
        // Most preferred first (by default secp384r1 then secp256r1). The BCL exposes no X25519 key
        // agreement, so x25519 is not offered; every browser supports P-256 and P-384.
        var data = new byte[2 + (groups.Count * 2)];
        data[0] = 0x00;
        data[1] = (byte)(groups.Count * 2);
        for (var i = 0; i < groups.Count; i++)
        {
            data[2 + (i * 2)] = (byte)(groups[i] >> 8);
            data[3 + (i * 2)] = (byte)groups[i];
        }

        WriteExtension(ref writer, ExtensionTypes.SupportedGroups, data);
    }

    private static void WriteEcPointFormats(ref ByteWriter writer)
    {
        byte[] data = [0x01, 0x00]; // one format: uncompressed
        WriteExtension(ref writer, ExtensionTypes.EcPointFormats, data);
    }

    private static void WriteSignatureAlgorithms(ref ByteWriter writer)
    {
        ReadOnlySpan<SigHashAlgorithm> algorithms =
        [
            SigHashAlgorithm.EcdsaSha256,
            SigHashAlgorithm.RsaSha256,
        ];

        var data = new byte[2 + (algorithms.Length * 2)];
        data[0] = 0x00;
        data[1] = (byte)(algorithms.Length * 2);
        for (var i = 0; i < algorithms.Length; i++)
        {
            data[2 + (i * 2)] = algorithms[i].Hash;
            data[3 + (i * 2)] = algorithms[i].Signature;
        }

        WriteExtension(ref writer, ExtensionTypes.SignatureAlgorithms, data);
    }

    private static void WriteUseSrtp(ref ByteWriter writer, IReadOnlyList<SrtpProtectionProfile> profiles)
    {
        if (profiles.Count == 0)
        {
            return;
        }

        var data = new byte[3 + (profiles.Count * 2)];
        data[0] = 0x00;
        data[1] = (byte)(profiles.Count * 2);
        for (var i = 0; i < profiles.Count; i++)
        {
            data[2 + (i * 2)] = (byte)((ushort)profiles[i] >> 8);
            data[3 + (i * 2)] = (byte)(ushort)profiles[i];
        }

        data[^1] = 0x00; // empty MKI
        WriteExtension(ref writer, ExtensionTypes.UseSrtp, data);
    }

    private static void PatchLength16(ref ByteWriter writer, int offset, int length)
    {
        var span = writer.Patch(offset, 2);
        span[0] = (byte)(length >> 8);
        span[1] = (byte)length;
    }
}
