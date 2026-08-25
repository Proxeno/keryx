using System.Net;
using System.Text;
using System.Text.Json;
using Xunit.Abstractions;

namespace Keryx.IntegrationTests;

/// <summary>
/// A tiny HTTP signaling host the browser interop lanes share. It serves the one role-flexible
/// fixture (<c>assets/chrome-client.html</c>) on <c>/</c> and covers every signaling shape the fixture
/// drives, so both the keryx-offers flow and the browser-offers (SFU) flows run against one host:
/// <list type="bullet">
/// <item><c>GET /offer</c> — hands the browser Keryx's offer (Keryx is the offerer; role=answer).</item>
/// <item><c>POST /answer</c> — takes the browser's answer to that offer.</item>
/// <item><c>POST /offer</c> — takes the browser's offer and returns Keryx's answer in the response
/// (the browser is the offerer; role=offer-send / offer-recv).</item>
/// <item><c>POST /report</c> — collects the browser's periodic JSON status snapshots.</item>
/// </list>
/// The seam is engine agnostic: the same host drives Chrome or Firefox unchanged.
/// </summary>
internal sealed class InteropSignalingHost : IDisposable
{
    private readonly HttpListener _listener = new();
    private readonly ITestOutputHelper _output;

    /// <summary>Creates a host bound to loopback on <paramref name="port"/>.</summary>
    /// <param name="port">The loopback TCP port to listen on.</param>
    /// <param name="output">Where handler errors are logged.</param>
    internal InteropSignalingHost(int port, ITestOutputHelper output)
    {
        _listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        _output = output;
    }

    /// <summary>Supplies Keryx's offer SDP for <c>GET /offer</c> (the keryx-offers flow).</summary>
    internal Func<Task<string>>? OnGetOffer { get; set; }

    /// <summary>Handles <c>POST /answer</c>: the browser's answer SDP to Keryx's offer.</summary>
    internal Func<string, Task>? OnAnswer { get; set; }

    /// <summary>Handles <c>POST /offer</c>: takes the browser offer SDP, returns Keryx's answer SDP.</summary>
    internal Func<string, Task<string>>? OnPostOffer { get; set; }

    /// <summary>Handles <c>POST /report</c>: receives one browser status snapshot as JSON.</summary>
    internal Action<string> OnReport { get; set; } = _ => { };

    /// <summary>Starts serving until <paramref name="cancellationToken"/> fires or the host is disposed.</summary>
    /// <param name="cancellationToken">Stops the accept loop.</param>
    internal void Start(CancellationToken cancellationToken)
    {
        _listener.Start();
        _ = Task.Run(async () =>
        {
            while (_listener.IsListening)
            {
                HttpListenerContext context;
                try
                {
                    context = await _listener.GetContextAsync().ConfigureAwait(false);
                }
                catch (Exception) when (!_listener.IsListening || cancellationToken.IsCancellationRequested)
                {
                    return;
                }

                try
                {
                    await HandleAsync(context).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _output.WriteLine($"signaling host error: {ex.Message}");
                }
            }
        });
    }

    private async Task HandleAsync(HttpListenerContext context)
    {
        var request = context.Request;
        var response = context.Response;
        switch (request.Url?.AbsolutePath)
        {
            case "/":
                var html = await File.ReadAllBytesAsync(
                    Path.Combine(AppContext.BaseDirectory, "assets", "chrome-client.html"));
                response.ContentType = "text/html";
                await response.OutputStream.WriteAsync(html);
                break;
            case "/offer" when request.HttpMethod == "GET":
                var offerSdp = OnGetOffer is null ? string.Empty : await OnGetOffer();
                var offerJson = JsonSerializer.SerializeToUtf8Bytes(new { type = "offer", sdp = offerSdp });
                response.ContentType = "application/json";
                await response.OutputStream.WriteAsync(offerJson);
                break;
            case "/offer":
                using (var reader = new StreamReader(request.InputStream, Encoding.UTF8))
                {
                    var body = await reader.ReadToEndAsync();
                    using var doc = JsonDocument.Parse(body);
                    var browserOffer = doc.RootElement.GetProperty("sdp").GetString()!;
                    var answerSdp = OnPostOffer is null ? string.Empty : await OnPostOffer(browserOffer);
                    var answerJson = JsonSerializer.SerializeToUtf8Bytes(new { type = "answer", sdp = answerSdp });
                    response.ContentType = "application/json";
                    await response.OutputStream.WriteAsync(answerJson);
                }

                break;
            case "/answer":
                using (var reader = new StreamReader(request.InputStream, Encoding.UTF8))
                {
                    var body = await reader.ReadToEndAsync();
                    using var doc = JsonDocument.Parse(body);
                    var sdp = doc.RootElement.GetProperty("sdp").GetString()!;
                    if (OnAnswer is not null)
                    {
                        await OnAnswer(sdp);
                    }
                }

                break;
            case "/report":
                using (var reader = new StreamReader(request.InputStream, Encoding.UTF8))
                {
                    OnReport(await reader.ReadToEndAsync());
                }

                break;
            default:
                response.StatusCode = 404;
                break;
        }

        response.Close();
    }

    /// <summary>Stops the listener; never throws.</summary>
    public void Dispose()
    {
        try
        {
            _listener.Stop();
            _listener.Close();
        }
        catch (Exception)
        {
            // best effort
        }
    }
}
