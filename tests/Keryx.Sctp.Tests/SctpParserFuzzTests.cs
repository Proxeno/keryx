using Keryx.Core;
using Xunit;

namespace Keryx.Sctp.Tests;

/// <summary>
/// Seeded, deterministic generative fuzzers for the inbound SCTP packet/chunk parser
/// (<see cref="SctpPacket.Parse(System.ReadOnlySpan{byte}, bool)"/> and every chunk/parameter body
/// parser it dispatches to). This is the code that reads bytes straight off DTLS from a remote peer,
/// so it is a prime attack surface for the planned security review.
/// </summary>
/// <remarks>
/// The robustness contract the fuzzers assert: for <em>any</em> byte input the parser must either
/// parse successfully or reject cleanly by throwing <see cref="ByteBufferException"/> — the one typed,
/// controlled failure the layer documents. It must never throw any other (unhandled) exception type,
/// never read out of bounds, and never allocate unboundedly relative to its input. Semantic
/// correctness of garbage is explicitly <em>not</em> asserted; only robustness is.
///
/// Everything is driven by a fixed set of PRNG seeds so a CI failure reproduces exactly. On any
/// violation the failing seed, mutation strategy and the full hex of the offending input are logged.
/// </remarks>
public class SctpParserFuzzTests
{
    // Fixed iteration budget per seed. Kept modest so the whole suite is fast and deterministic; the
    // parser is provably linear so this is ample coverage per run, and the seed set is what provides
    // breadth across runs.
    private const int IterationsPerSeed = 4000;

    // A fixed, deterministic seed set. Reproduces byte-for-byte on every run and in CI.
    private static readonly int[] Seeds = [1, 7, 42, 99, 1234, 20260824];

    /// <summary>
    /// Structure-aware mutation fuzzer: starts from a corpus of well-formed packets the stack itself
    /// builds (INIT with parameters, DATA, I-DATA, SACK with gap/dup blocks, FORWARD TSN, RE-CONFIG,
    /// HEARTBEAT, ABORT/ERROR with causes, COOKIE ECHO, SHUTDOWN, and multi-chunk packets) then applies
    /// byte-level corruption: bit flips, length-field corruption, truncation, oversized counts,
    /// duplicated/appended bytes and integer-overflow lengths.
    /// </summary>
    [Fact]
    public void Fuzz_StructureAwareMutations_NeverThrowUncontrolled()
    {
        var corpus = BuildCorpus();
        foreach (var seed in Seeds)
        {
            var rng = new Random(seed);
            for (var i = 0; i < IterationsPerSeed; i++)
            {
                var original = corpus[rng.Next(corpus.Count)];
                var mutated = Mutate(original, rng, out var strategy);
                AssertRobust(mutated, seed, i, strategy);
            }
        }
    }

    /// <summary>
    /// Total-garbage fuzzer: random byte blobs of widely varied lengths, including sub-header sizes
    /// (0–11 bytes), header-sized and larger buffers up to a few KB. Nothing here is expected to parse;
    /// the point is that rejection is always clean.
    /// </summary>
    [Fact]
    public void Fuzz_TotalGarbage_NeverThrowUncontrolled()
    {
        foreach (var seed in Seeds)
        {
            var rng = new Random(seed ^ 0x5EED);
            for (var i = 0; i < IterationsPerSeed; i++)
            {
                var length = rng.Next(4) switch
                {
                    0 => rng.Next(0, 12),      // sub-common-header
                    1 => rng.Next(12, 64),     // small
                    2 => rng.Next(64, 512),    // medium
                    _ => rng.Next(512, 4096),  // large
                };
                var blob = new byte[length];
                rng.NextBytes(blob);
                AssertRobust(blob, seed, i, "garbage");
            }
        }
    }

    /// <summary>
    /// A fixed table of hand-picked adversarial inputs that exercise specific boundary conditions
    /// regardless of the PRNG, plus permanent regression coverage for anything a fuzz run surfaces.
    /// </summary>
    [Theory]
    [MemberData(nameof(EdgeCases))]
    public void EdgeCase_ParsesOrRejectsCleanly(string name, byte[] input)
    {
        AssertRobust(input, seed: -1, iteration: -1, strategy: name);
    }

    public static TheoryData<string, byte[]> EdgeCases()
    {
        var data = new TheoryData<string, byte[]>
        {
            { "empty", [] },
            { "one-byte", [0x00] },
            { "header-only-zeros", new byte[12] },
            // Common header + a chunk header claiming length 0 (invalid, must reject).
            { "chunk-length-zero", Concat(new byte[12], [0x00, 0x00, 0x00, 0x00]) },
            // Chunk header claiming length 3 (< 4 minimum, must reject).
            { "chunk-length-below-min", Concat(new byte[12], [0x00, 0x00, 0x00, 0x03]) },
            // DATA chunk claiming a body far larger than what is present (must reject).
            { "data-length-overflow", Concat(new byte[12], [0x00, 0x00, 0xFF, 0xFF]) },
            // SACK claiming 0xFFFF gap and 0xFFFF dup blocks with no room for them (must reject).
            {
                "sack-oversized-counts",
                Concat(new byte[12], [0x03, 0x00, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF])
            },
            // INIT with a parameter whose length field claims 0xFFFF (must reject).
            {
                "init-param-length-overflow",
                Concat(
                    new byte[12],
                    [0x01, 0x00, 0x00, 0x18, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0x80, 0x08, 0xFF, 0xFF])
            },
        };
        return data;
    }

    private static void AssertRobust(byte[] input, int seed, int iteration, string strategy)
    {
        // Exercise the real inbound entry point. verifyChecksum:false is deliberate: a remote attacker
        // computes a valid CRC-32C themselves, so the deep chunk parsers must be robust independent of
        // the checksum gate. We also run the verifyChecksum:true branch to cover the checksum path.
        RunOnce(input, verifyChecksum: false, seed, iteration, strategy);
        RunOnce(input, verifyChecksum: true, seed, iteration, strategy);
    }

    private static void RunOnce(byte[] input, bool verifyChecksum, int seed, int iteration, string strategy)
    {
        try
        {
            var packet = SctpPacket.Parse(input, verifyChecksum);

            // Robustness invariants on a successful parse: the number of decoded chunks can never
            // exceed the input size (each chunk consumes at least its 4-byte header), which would be
            // the tell-tale of an unbounded-allocation bug.
            Assert.True(
                packet.Chunks.Count <= input.Length,
                $"decoded {packet.Chunks.Count} chunks from {input.Length} bytes");
        }
        catch (ByteBufferException)
        {
            // Controlled, documented rejection of malformed input. This is the acceptable failure mode.
        }
        catch (Exception ex)
        {
            Assert.Fail(
                $"SCTP parser threw uncontrolled {ex.GetType().FullName} " +
                $"(verifyChecksum={verifyChecksum}, strategy={strategy}, seed={seed}, iter={iteration}): " +
                $"{ex.Message}\ninput={Convert.ToHexString(input)}");
        }
    }

    // ---- Mutation engine ------------------------------------------------------------------------

    private static byte[] Mutate(byte[] source, Random rng, out string strategy)
    {
        var buffer = (byte[])source.Clone();
        var choice = rng.Next(9);
        switch (choice)
        {
            case 0:
                strategy = "bit-flip";
                for (var n = 0; n < 1 + rng.Next(8) && buffer.Length > 0; n++)
                {
                    var index = rng.Next(buffer.Length);
                    buffer[index] ^= (byte)(1 << rng.Next(8));
                }

                return buffer;

            case 1:
                strategy = "byte-set";
                for (var n = 0; n < 1 + rng.Next(6) && buffer.Length > 0; n++)
                {
                    var index = rng.Next(buffer.Length);
                    buffer[index] = rng.Next(3) switch { 0 => 0x00, 1 => 0xFF, _ => (byte)rng.Next(256) };
                }

                return buffer;

            case 2:
                strategy = "truncate";
                return buffer.Length == 0 ? buffer : buffer[..rng.Next(buffer.Length)];

            case 3:
                strategy = "corrupt-16bit-length";
                if (buffer.Length >= 2)
                {
                    var index = rng.Next(buffer.Length - 1);
                    var value = rng.Next(4) switch
                    {
                        0 => 0x0000,
                        1 => 0x0003,
                        2 => 0xFFFF,
                        _ => rng.Next(0x10000),
                    };
                    buffer[index] = (byte)(value >> 8);
                    buffer[index + 1] = (byte)value;
                }

                return buffer;

            case 4:
                strategy = "append-random";
                var extra = new byte[rng.Next(1, 64)];
                rng.NextBytes(extra);
                return Concat(buffer, extra);

            case 5:
                strategy = "duplicate-tail";
                if (buffer.Length <= SctpPacket.CommonHeaderLength)
                {
                    return buffer;
                }

                var tail = buffer[SctpPacket.CommonHeaderLength..];
                var copies = 1 + rng.Next(4);
                var result = buffer;
                for (var c = 0; c < copies; c++)
                {
                    result = Concat(result, tail);
                }

                // Cap growth so the test stays fast and deterministic.
                return result.Length > 8192 ? result[..8192] : result;

            case 6:
                strategy = "insert-oversized-count";
                if (buffer.Length >= 4)
                {
                    var index = rng.Next(buffer.Length - 3);
                    buffer[index] = 0xFF;
                    buffer[index + 1] = 0xFF;
                    buffer[index + 2] = 0xFF;
                    buffer[index + 3] = 0xFF;
                }

                return buffer;

            case 7:
                strategy = "zero-region";
                if (buffer.Length > 0)
                {
                    var start = rng.Next(buffer.Length);
                    var end = Math.Min(buffer.Length, start + rng.Next(1, 16));
                    for (var k = start; k < end; k++)
                    {
                        buffer[k] = 0;
                    }
                }

                return buffer;

            default:
                strategy = "prepend-chunk-type";
                // Force the first chunk type byte to a random value so every dispatch arm is exercised.
                if (buffer.Length > SctpPacket.CommonHeaderLength)
                {
                    buffer[SctpPacket.CommonHeaderLength] = (byte)rng.Next(256);
                }

                return buffer;
        }
    }

    // ---- Valid corpus ---------------------------------------------------------------------------

    private static List<byte[]> BuildCorpus()
    {
        var corpus = new List<byte[]>();

        // INIT with the parameters Chrome actually sends.
        var init = new SctpInitChunk(SctpChunkType.Init)
        {
            InitiateTag = 0x12345678,
            AdvertisedReceiverWindow = 131072,
            NumberOfOutboundStreams = 1024,
            NumberOfInboundStreams = 1024,
            InitialTsn = 42,
        };
        init.Parameters.Add(new SctpParameter(SctpParameterType.ForwardTsnSupported, []));
        init.Parameters.Add(new SctpParameter(
            SctpParameterType.SupportedExtensions,
            [(byte)SctpChunkType.ForwardTsn, (byte)SctpChunkType.ReConfig, (byte)SctpChunkType.IData]));
        corpus.Add(Packet(init));

        // INIT ACK carrying a state cookie.
        var initAck = new SctpInitChunk(SctpChunkType.InitAck)
        {
            InitiateTag = 0xABCDEF01,
            AdvertisedReceiverWindow = 131072,
            NumberOfOutboundStreams = 1024,
            NumberOfInboundStreams = 1024,
            InitialTsn = 7,
        };
        initAck.Parameters.Add(new SctpParameter(SctpParameterType.StateCookie, RandomBytes(64, 0x01)));
        corpus.Add(Packet(initAck));

        // DATA chunk with a DCEP-string payload.
        corpus.Add(Packet(new SctpDataChunk(100, 3, 0, SctpPpid.String, "hello data channel"u8.ToArray())));

        // I-DATA first fragment.
        corpus.Add(Packet(new SctpIDataChunk(101, 3, 5, SctpPpid.Binary, 0, RandomBytes(40, 0x02))));

        // SACK with gap and duplicate blocks.
        var sack = new SctpSackChunk { CumulativeTsnAck = 99, AdvertisedReceiverWindow = 65536 };
        sack.GapAckBlocks.Add(new SctpGapAckBlock(2, 4));
        sack.GapAckBlocks.Add(new SctpGapAckBlock(6, 6));
        sack.DuplicateTsns.Add(98);
        sack.DuplicateTsns.Add(97);
        corpus.Add(Packet(sack));

        // FORWARD TSN with per-stream entries.
        var forward = new SctpForwardTsnChunk { NewCumulativeTsn = 150 };
        forward.Streams.Add(new SctpForwardTsnStream(3, 10));
        forward.Streams.Add(new SctpForwardTsnStream(4, 2));
        corpus.Add(Packet(forward));

        // RE-CONFIG with an outgoing SSN reset request.
        corpus.Add(Packet(new SctpReConfigChunk(
            new SctpOutgoingSsnResetRequest(1, 0, 149, new ushort[] { 3, 4 }),
            new SctpReconfigResponse(0, SctpReconfigResult.SuccessPerformed))));

        // HEARTBEAT / HEARTBEAT ACK.
        corpus.Add(Packet(new SctpHeartbeatChunk(SctpChunkType.Heartbeat, RandomBytes(24, 0x03))));

        // ABORT and ERROR with causes.
        var abort = new SctpAbortChunk { TagReflected = true };
        abort.Causes.Add(new SctpErrorCause(SctpErrorCauseCode.ProtocolViolation, "bad"u8.ToArray()));
        corpus.Add(Packet(abort));

        var error = new SctpErrorChunk();
        error.Causes.Add(new SctpErrorCause(SctpErrorCauseCode.InvalidStreamIdentifier, [0, 5, 0, 0]));
        corpus.Add(Packet(error));

        // Small control chunks.
        corpus.Add(Packet(new SctpCookieEchoChunk(RandomBytes(48, 0x04))));
        corpus.Add(Packet(new SctpCookieAckChunk()));
        corpus.Add(Packet(new SctpShutdownChunk(200)));
        corpus.Add(Packet(new SctpShutdownAckChunk()));
        corpus.Add(Packet(new SctpShutdownCompleteChunk()));

        // A multi-chunk packet (SACK + DATA + FORWARD TSN together).
        var multi = new SctpPacket(5000, 5000, 0xDEADBEEF);
        multi.Chunks.Add(sack);
        multi.Chunks.Add(new SctpDataChunk(200, 1, 0, SctpPpid.Binary, RandomBytes(17, 0x05)));
        multi.Chunks.Add(forward);
        corpus.Add(multi.ToArray());

        return corpus;
    }

    private static byte[] Packet(SctpChunk chunk)
    {
        var packet = new SctpPacket(5000, 5000, 0x0BADF00D);
        packet.Chunks.Add(chunk);
        return packet.ToArray();
    }

    private static byte[] RandomBytes(int count, int seed)
    {
        var bytes = new byte[count];
        new Random(seed).NextBytes(bytes);
        return bytes;
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result, 0);
        b.CopyTo(result, a.Length);
        return result;
    }
}
