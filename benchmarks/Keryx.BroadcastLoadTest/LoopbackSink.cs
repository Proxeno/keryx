using System.Net;
using System.Net.Sockets;
using Keryx.Rtp;
using Keryx.Srtp;

namespace Keryx.BroadcastLoadTest;

/// <summary>
/// One lightweight viewer receiver for the fan-out ceiling arms: a real, distinct loopback UDP socket
/// (its own 5-tuple, so the shared socket's <c>sendmmsg</c> addresses N real destinations exactly as it
/// would N real viewers) plus that viewer's own SRTP decrypt context. The receive loop drains the socket
/// so a full receive buffer never back-pressures the sender into an artificial drop, and decrypts a
/// sampled fraction of datagrams to prove the media the sender encrypted actually authenticates and
/// carries the right SSRC — real crypto on the wire, without paying a full 6M-decrypt/s receive tax that
/// would compete with the send ceiling being measured.
/// </summary>
internal sealed class LoopbackSink : IDisposable
{
    // Decrypt one datagram in this many; the rest are drained only. Enough coverage to catch a
    // mis-encrypted or cross-wired stream without the receive side stealing the cores under measurement.
    private const int DecryptSample = 64;

    private readonly Socket _socket;
    private readonly SrtpDecryptContext _decrypt;
    private readonly uint _expectedSsrc;
    private readonly byte[] _recovered = new byte[2048];

    public LoopbackSink(uint expectedSsrc, SrtpProtectionProfile profile, SrtpSessionKeys keys, int receiveBufferBytes)
    {
        _expectedSsrc = expectedSsrc;
        _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)
        {
            ReceiveBufferSize = receiveBufferBytes,
        };
        _socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        LocalEndPoint = (IPEndPoint)_socket.LocalEndPoint!;
        _decrypt = new SrtpDecryptContext(profile, keys);
    }

    public IPEndPoint LocalEndPoint { get; }

    public long Received;
    public long Decrypted;
    public long DecryptFailures;
    public long ForeignSsrc;

    public async Task ReceiveLoopAsync(CancellationToken cancellationToken)
    {
        var buffer = new byte[2048];
        var n = 0L;
        while (!cancellationToken.IsCancellationRequested)
        {
            int len;
            try
            {
                len = await _socket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (SocketException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }

            Interlocked.Increment(ref Received);

            // Decrypt a sampled fraction: enough to prove correctness, cheap enough not to distort the send
            // ceiling. A sampled datagram must authenticate under this viewer's own key and carry its SSRC.
            if (n++ % DecryptSample == 0)
            {
                if (!_decrypt.TryUnprotectRtp(buffer.AsSpan(0, len), _recovered, out var recovered))
                {
                    Interlocked.Increment(ref DecryptFailures);
                }
                else if (!RtpHeader.TryParse(_recovered.AsSpan(0, recovered), out var header) || header.Ssrc != _expectedSsrc)
                {
                    Interlocked.Increment(ref ForeignSsrc);
                }
                else
                {
                    Interlocked.Increment(ref Decrypted);
                }
            }
        }
    }

    public void Dispose()
    {
        _socket.Dispose();
        _decrypt.Dispose();
    }
}
