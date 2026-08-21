using Xunit;
using Xunit.Abstractions;

namespace Keryx.Srtp.Tests;

public class TmpAlloc
{
    private readonly ITestOutputHelper _out;
    public TmpAlloc(ITestOutputHelper o) => _out = o;

    [Theory]
    [InlineData(SrtpProtectionProfileKind.Aes128CmHmacSha1_80)]
    [InlineData(SrtpProtectionProfileKind.AeadAes128Gcm)]
    public void Measure(SrtpProtectionProfileKind kind)
    {
        var profile = SrtpProtectionProfile.ForKind(kind);
        var keys = DtlsSrtpKeyMaterial.Split(profile, TestPackets.KeyingMaterial(1, profile), DtlsSrtpRole.Client);
        using var s = new SrtpEncryptContext(profile, keys.Local);
        using var r = new SrtpDecryptContext(profile, keys.Local);
        var payload = new byte[1200];
        var packet = TestPackets.Rtp(1, 0, 0, payload);
        var buf = new byte[packet.Length + 32];
        var outBuf = new byte[packet.Length + 32];

        // warm up
        for (int i = 0; i < 200; i++) { var n = s.ProtectRtp(packet, buf); r.TryUnprotectRtp(buf.AsSpan(0, n), outBuf, out _); }

        var before = GC.GetAllocatedBytesForCurrentThread();
        const int iters = 2000;
        for (int i = 0; i < iters; i++) { var n = s.ProtectRtp(packet, buf); r.TryUnprotectRtp(buf.AsSpan(0, n), outBuf, out _); }
        var after = GC.GetAllocatedBytesForCurrentThread();
        _out.WriteLine($"{kind}: {(after - before) / (double)iters:F1} bytes per protect+unprotect pair");
    }
}
