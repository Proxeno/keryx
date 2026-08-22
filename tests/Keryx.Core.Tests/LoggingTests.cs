using FluentAssertions;
using Xunit;

namespace Keryx.Core.Tests;

public class LoggingTests
{
    [Theory]
    [InlineData(KeryxLogLevel.Trace)]
    [InlineData(KeryxLogLevel.Debug)]
    [InlineData(KeryxLogLevel.Info)]
    [InlineData(KeryxLogLevel.Warning)]
    [InlineData(KeryxLogLevel.Error)]
    public void NullLogger_IsEnabled_AlwaysFalse(KeryxLogLevel level)
    {
        NullLogger.Instance.IsEnabled(level).Should().BeFalse();
    }

    [Fact]
    public void NullLogger_Log_IsNoOp()
    {
        var act = () => NullLogger.Instance.Log(KeryxLogLevel.Error, "boom", new InvalidOperationException("x"));

        act.Should().NotThrow();
    }

    [Fact]
    public void NullLogger_Instance_IsSingleton()
    {
        NullLogger.Instance.Should().BeSameAs(NullLogger.Instance);
    }

    [Fact]
    public void TextWriterLogger_Constructor_NullWriter_Throws()
    {
        var act = () => new TextWriterLogger(null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void TextWriterLogger_Constructor_NullName_Throws()
    {
        using var writer = new StringWriter();

        var act = () => new TextWriterLogger(writer, KeryxLogLevel.Info, null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Theory]
    [InlineData(KeryxLogLevel.Trace, KeryxLogLevel.Trace, true)]
    [InlineData(KeryxLogLevel.Debug, KeryxLogLevel.Trace, true)]
    [InlineData(KeryxLogLevel.Info, KeryxLogLevel.Trace, true)]
    [InlineData(KeryxLogLevel.Trace, KeryxLogLevel.Debug, false)]
    [InlineData(KeryxLogLevel.Debug, KeryxLogLevel.Debug, true)]
    [InlineData(KeryxLogLevel.Warning, KeryxLogLevel.Error, false)]
    [InlineData(KeryxLogLevel.Error, KeryxLogLevel.Error, true)]
    public void TextWriterLogger_IsEnabled_ReflectsMinimumThreshold(
        KeryxLogLevel level, KeryxLogLevel minimum, bool expected)
    {
        using var writer = new StringWriter();
        var logger = new TextWriterLogger(writer, minimum);

        logger.IsEnabled(level).Should().Be(expected);
    }

    [Fact]
    public void TextWriterLogger_DefaultMinimum_IsInfo()
    {
        using var writer = new StringWriter();
        var logger = new TextWriterLogger(writer);

        logger.IsEnabled(KeryxLogLevel.Debug).Should().BeFalse();
        logger.IsEnabled(KeryxLogLevel.Info).Should().BeTrue();
    }

    [Fact]
    public void TextWriterLogger_Log_BelowMinimum_WritesNothing()
    {
        using var writer = new StringWriter();
        var logger = new TextWriterLogger(writer, KeryxLogLevel.Warning);

        logger.Log(KeryxLogLevel.Info, "should not appear");

        writer.ToString().Should().BeEmpty();
    }

    [Fact]
    public void TextWriterLogger_Log_AtMinimum_Writes()
    {
        using var writer = new StringWriter();
        var logger = new TextWriterLogger(writer, KeryxLogLevel.Warning);

        logger.Log(KeryxLogLevel.Warning, "at threshold");

        writer.ToString().Should().NotBeEmpty();
    }

    [Fact]
    public void TextWriterLogger_Log_AboveMinimum_Writes()
    {
        using var writer = new StringWriter();
        var logger = new TextWriterLogger(writer, KeryxLogLevel.Warning);

        logger.Log(KeryxLogLevel.Error, "above threshold");

        writer.ToString().Should().NotBeEmpty();
    }

    [Fact]
    public void TextWriterLogger_Log_MessageContainsLevelNameAndMessage()
    {
        using var writer = new StringWriter();
        var logger = new TextWriterLogger(writer, KeryxLogLevel.Trace, "my-component");

        logger.Log(KeryxLogLevel.Warning, "something happened");

        var output = writer.ToString();
        output.Should().Contain("Warning");
        output.Should().Contain("my-component");
        output.Should().Contain("something happened");
    }

    [Fact]
    public void TextWriterLogger_Log_DefaultName_IsKeryx()
    {
        using var writer = new StringWriter();
        var logger = new TextWriterLogger(writer, KeryxLogLevel.Trace);

        logger.Log(KeryxLogLevel.Info, "hello");

        writer.ToString().Should().Contain("keryx");
    }

    [Fact]
    public void TextWriterLogger_Log_WithoutException_OmitsExceptionSection()
    {
        using var writer = new StringWriter();
        var logger = new TextWriterLogger(writer, KeryxLogLevel.Trace);

        logger.Log(KeryxLogLevel.Info, "plain message");

        writer.ToString().Should().NotContain(" | ");
    }

    [Fact]
    public void TextWriterLogger_Log_WithException_IncludesTypeAndMessage()
    {
        using var writer = new StringWriter();
        var logger = new TextWriterLogger(writer, KeryxLogLevel.Trace, "comp");
        var exception = new InvalidOperationException("bad state");

        logger.Log(KeryxLogLevel.Error, "operation failed", exception);

        var output = writer.ToString();
        output.Should().Contain("operation failed");
        output.Should().Contain(nameof(InvalidOperationException));
        output.Should().Contain("bad state");
    }

    [Fact]
    public void TextWriterLogger_Log_BelowMinimum_DoesNotFormatOrTouchException()
    {
        using var writer = new StringWriter();
        var logger = new TextWriterLogger(writer, KeryxLogLevel.Error);

        logger.Log(KeryxLogLevel.Trace, "ignored", new InvalidOperationException("ignored too"));

        writer.ToString().Should().BeEmpty();
    }

    [Fact]
    public void TextWriterLogger_Log_EachCall_WritesOneLine()
    {
        using var writer = new StringWriter();
        var logger = new TextWriterLogger(writer, KeryxLogLevel.Trace);

        logger.Log(KeryxLogLevel.Info, "first");
        logger.Log(KeryxLogLevel.Info, "second");

        var lines = writer.ToString().Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
        lines.Should().HaveCount(2);
        lines[0].Should().Contain("first");
        lines[1].Should().Contain("second");
    }
}
