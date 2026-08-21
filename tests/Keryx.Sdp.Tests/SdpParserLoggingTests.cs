using FluentAssertions;
using Keryx.Core;
using Xunit;

namespace Keryx.Sdp.Tests;

public class SdpParserLoggingTests
{
    private sealed class CollectingLogger : IKeryxLogger
    {
        public List<string> Messages { get; } = [];

        public bool IsEnabled(KeryxLogLevel level) => true;

        public void Log(KeryxLogLevel level, string message, Exception? exception = null) =>
            Messages.Add(message);
    }

    [Fact]
    public void Parse_LogsSkippedLines()
    {
        var logger = new CollectingLogger();
        const string body = """
            v=0
            o=- 1 2 IN IP4 127.0.0.1
            s=-
            this is not sdp
            t=0 0
            """;

        SessionDescription.Parse(SdpTestData.Crlf(body), logger);

        logger.Messages.Should().ContainSingle()
            .Which.Should().Contain("this is not sdp").And.Contain("not a <type>=<value> line");
    }

    [Fact]
    public void Parse_LogsUnknownLineTypes()
    {
        var logger = new CollectingLogger();
        const string body = """
            v=0
            o=- 1 2 IN IP4 127.0.0.1
            s=-
            t=0 0
            q=mystery
            """;

        SessionDescription.Parse(SdpTestData.Crlf(body), logger);

        logger.Messages.Should().ContainSingle().Which.Should().Contain("unknown line type");
    }

    [Fact]
    public void Parse_LogsNothingForCleanInput()
    {
        var logger = new CollectingLogger();

        SessionDescription.Parse(SdpTestData.ChromeOffer, logger);

        logger.Messages.Should().BeEmpty();
    }

    [Fact]
    public void Parse_WithoutALoggerIsSafe()
    {
        var parse = () => SessionDescription.Parse("garbage", logger: null);

        parse.Should().NotThrow();
    }
}
