using System.Security.Cryptography;
using Xunit;
using Xunit.Abstractions;

namespace Keryx.Srtp.Tests;

public class TmpAlloc2
{
    private readonly ITestOutputHelper _out;
    public TmpAlloc2(ITestOutputHelper o) => _out = o;

    private void Measure(string name, Action a)
    {
        for (int i = 0; i < 500; i++) a();
        var before = GC.GetAllocatedBytesForCurrentThread();
        const int n = 5000;
        for (int i = 0; i < n; i++) a();
        var after = GC.GetAllocatedBytesForCurrentThread();
        _out.WriteLine($"{name}: {(after - before) / (double)n:F2} B/op");
    }

    [Fact]
    public void Primitives()
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = new byte[16];
        var src = new byte[1024];
        var dst = new byte[1024];
        Measure("Aes.EncryptEcb(1024)", () => aes.EncryptEcb(src, dst, PaddingMode.None));

        using var enc = aes.CreateEncryptor();
        Measure("ICryptoTransform.TransformBlock(1024)", () => enc.TransformBlock(src, 0, 1024, dst, 0));

        var key = new byte[20];
        var data = new byte[1250];
        var mac = new byte[20];
        Measure("HMACSHA1.HashData(1250)", () => HMACSHA1.HashData(key, data, mac));

        using var inc = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA1, key);
        Measure("IncrementalHash HMAC(1250)", () => { inc.AppendData(data); inc.GetHashAndReset(mac); });

        using var hmac = new HMACSHA1(key);
        Measure("HMACSHA1 instance TryComputeHash(1250)", () => hmac.TryComputeHash(data, mac, out _));

        using var gcm = new AesGcm(new byte[16], 16);
        var nonce = new byte[12];
        var ct = new byte[1200];
        var tag = new byte[16];
        var aad = new byte[12];
        Measure("AesGcm.Encrypt(1200)", () => gcm.Encrypt(nonce, data.AsSpan(0, 1200), ct, tag, aad));
    }
}
