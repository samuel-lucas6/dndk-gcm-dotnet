using System.Security.Cryptography;

namespace DndkGcmDotNet.Tests;

[TestClass]
public class DndkGcmTests
{
    // https://datatracker.ietf.org/doc/html/draft-gueron-cfrg-dndkgcm-00#appendix-B
    public static IEnumerable<object[]> TestVectors()
    {
        yield return
        [
            "e6de36f2e5973b407bafcd39a20f92ac8d1f5629",
            "11000001",
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "0100000011",
            false
        ];
        yield return
        [
            "e6de36f2e5973b407bafcd39a20f92ac8d1f56291fd1839805fce095052919629ca8947766d08eeee135cdf261228bfd4a796bbb",
            "11000001",
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "0100000011",
            true
        ];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [ DndkGcm.TagSize, 1, DndkGcm.NonceSize, DndkGcm.KeySize, 0, false ];
        yield return [ DndkGcm.TagSize, 0, DndkGcm.NonceSize + 1, DndkGcm.KeySize, 0, false ];
        yield return [ DndkGcm.TagSize, 0, DndkGcm.NonceSize - 1, DndkGcm.KeySize, 0, false ];
        yield return [ DndkGcm.TagSize, 0, DndkGcm.NonceSize, DndkGcm.KeySize + 1, 0, false ];
        yield return [ DndkGcm.TagSize, 0, DndkGcm.NonceSize, DndkGcm.KeySize - 1, 0, false ];

        yield return [ DndkGcm.TagSize + DndkGcm.CommitmentSize, 1, DndkGcm.NonceSize, DndkGcm.KeySize, 0, true ];
        yield return [ DndkGcm.TagSize + DndkGcm.CommitmentSize, 0, DndkGcm.NonceSize + 1, DndkGcm.KeySize, 0, true ];
        yield return [ DndkGcm.TagSize + DndkGcm.CommitmentSize, 0, DndkGcm.NonceSize - 1, DndkGcm.KeySize, 0, true ];
        yield return [ DndkGcm.TagSize + DndkGcm.CommitmentSize, 0, DndkGcm.NonceSize, DndkGcm.KeySize + 1, 0, true ];
        yield return [ DndkGcm.TagSize + DndkGcm.CommitmentSize, 0, DndkGcm.NonceSize, DndkGcm.KeySize - 1, 0, true ];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, DndkGcm.KeySize);
        Assert.AreEqual(24, DndkGcm.NonceSize);
        Assert.AreEqual(16, DndkGcm.TagSize);
        Assert.AreEqual(32, DndkGcm.CommitmentSize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData, bool isKeyCommitting)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        DndkGcm.Encrypt(c, p, n, k, ad, isKeyCommitting);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize, bool isKeyCommitting)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => DndkGcm.Encrypt(c, p, n, k, ad, isKeyCommitting));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData, bool isKeyCommitting)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        DndkGcm.Decrypt(p, c, n, k, ad, isKeyCommitting);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Tampered(string ciphertext, string plaintext, string nonce, string key, string associatedData, bool isKeyCommitting)
    {
        var p = new byte[plaintext.Length / 2];
        var parameters = new List<byte[]>
        {
            Convert.FromHexString(ciphertext),
            Convert.FromHexString(nonce),
            Convert.FromHexString(key),
            Convert.FromHexString(associatedData)
        };

        foreach (var param in parameters.Where(param => param.Length > 0)) {
            for (int i = 0; i < param.Length; i += param.Length - 1) {
                param[i]++;
                Assert.ThrowsException<CryptographicException>(() => DndkGcm.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3], isKeyCommitting));
                param[i]--;
            }
        }
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize, bool isKeyCommitting)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => DndkGcm.Decrypt(p, c, n, k, ad, isKeyCommitting));
    }
}
