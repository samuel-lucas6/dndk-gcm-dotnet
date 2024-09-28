using System.Security.Cryptography;

namespace DndkGcmDotNet;

public static class DndkGcm
{
    public const int KeySize = 32;
    public const int NonceSize = 24;
    public const int TagSize = 16;
    public const int CommitmentSize = 32;
    private const int BlockSize = 16;

    public static bool IsSupported()
    {
        return AesGcm.IsSupported;
    }

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default, bool isKeyCommitting = true)
    {
        if (!IsSupported()) { throw new PlatformNotSupportedException("AES-GCM is not supported on this platform."); }
        switch (isKeyCommitting) {
            case true when ciphertext.Length != plaintext.Length + TagSize + CommitmentSize:
                throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be {plaintext.Length + TagSize + CommitmentSize} bytes long.");
            case false when ciphertext.Length != plaintext.Length + TagSize:
                throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be {plaintext.Length + TagSize} bytes long.");
        }
        if (nonce.Length != NonceSize) { throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, $"{nameof(nonce)} must be {NonceSize} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }

        Span<byte> subkey = stackalloc byte[KeySize];
        Derive(subkey, isKeyCommitting ? ciphertext[^CommitmentSize..] : Span<byte>.Empty, nonce, key);

        Span<byte> emptyNonce = stackalloc byte[NonceSize / 2];
        emptyNonce.Clear();
        using var aesGcm = new AesGcm(subkey, TagSize);
        aesGcm.Encrypt(emptyNonce, plaintext, isKeyCommitting ? ciphertext[..^(TagSize + CommitmentSize)] : ciphertext[..^TagSize], isKeyCommitting ? ciphertext[^(TagSize + CommitmentSize)..^CommitmentSize] : ciphertext[^TagSize..], associatedData);
        CryptographicOperations.ZeroMemory(subkey);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default, bool isKeyCommitting = true)
    {
        if (!IsSupported()) { throw new PlatformNotSupportedException("AES-GCM is not supported on this platform."); }
        switch (isKeyCommitting) {
            case true when ciphertext.Length < TagSize + CommitmentSize:
                throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be at least {TagSize + CommitmentSize} bytes long.");
            case false when ciphertext.Length < TagSize:
                throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be at least {TagSize} bytes long.");
            case true when plaintext.Length != ciphertext.Length - TagSize - CommitmentSize:
                throw new ArgumentOutOfRangeException(nameof(plaintext), plaintext.Length, $"{nameof(plaintext)} must be {ciphertext.Length - TagSize - CommitmentSize} bytes long.");
            case false when plaintext.Length != ciphertext.Length - TagSize:
                throw new ArgumentOutOfRangeException(nameof(plaintext), plaintext.Length, $"{nameof(plaintext)} must be {ciphertext.Length - TagSize} bytes long.");
        }
        if (nonce.Length != NonceSize) { throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, $"{nameof(nonce)} must be {NonceSize} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }

        Span<byte> subkey = stackalloc byte[KeySize], commitment = isKeyCommitting ? stackalloc byte[CommitmentSize] : Span<byte>.Empty;
        Derive(subkey, commitment, nonce, key);

        try {
            if (isKeyCommitting && !CryptographicOperations.FixedTimeEquals(commitment, ciphertext[^CommitmentSize..])) {
                throw new CryptographicException();
            }

            Span<byte> emptyNonce = stackalloc byte[NonceSize / 2];
            emptyNonce.Clear();
            using var aesGcm = new AesGcm(subkey, TagSize);
            aesGcm.Decrypt(emptyNonce, isKeyCommitting ? ciphertext[..^(TagSize + CommitmentSize)] : ciphertext[..^TagSize], isKeyCommitting ? ciphertext[^(TagSize + CommitmentSize)..^CommitmentSize] : ciphertext[^TagSize..], plaintext, associatedData);
        }
        catch (AuthenticationTagMismatchException) {
            throw new CryptographicException();
        }
        finally {
            CryptographicOperations.ZeroMemory(subkey);
            CryptographicOperations.ZeroMemory(commitment);
        }
    }

    private static void Derive(Span<byte> subkey, Span<byte> commitment, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
    {
        int blockCount = !commitment.IsEmpty ? 10 : 6;
        ReadOnlySpan<byte> n0 = nonce[..(NonceSize / 2)], n1 = nonce[(NonceSize / 2)..];
        Span<byte> blocks = stackalloc byte[BlockSize * blockCount];
        blocks.Clear();
        for (int i = 0; i < blockCount; i++) {
            blocks[i * BlockSize] = (byte)i;
            ReadOnlySpan<byte> nonceHalf = i % 2 == 0 ? n0 : n1;
            nonceHalf.CopyTo(blocks.Slice(i * BlockSize + 4, nonceHalf.Length));
        }

        using var aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(blocks, blocks, PaddingMode.None);

        Span<byte> b0 = blocks[..BlockSize];
        Span<byte> b1 = blocks.Slice(BlockSize, BlockSize);
        Span<byte> b2 = blocks.Slice(BlockSize * 2, BlockSize);
        Span<byte> b3 = blocks.Slice(BlockSize * 3, BlockSize);
        Span<byte> b4 = blocks.Slice(BlockSize * 4, BlockSize);
        Span<byte> b5 = blocks.Slice(BlockSize * 5, BlockSize);

        Xor(b2, b0);
        Xor(b3, b1);
        Xor(b4, b0);
        Xor(b5, b1);

        Xor(subkey[..BlockSize], b2, b3);
        Xor(subkey[BlockSize..], b4, b5);

        if (!commitment.IsEmpty) {
            Span<byte> b6 = blocks.Slice(BlockSize * 6, BlockSize);
            Span<byte> b7 = blocks.Slice(BlockSize * 7, BlockSize);
            Span<byte> b8 = blocks.Slice(BlockSize * 8, BlockSize);
            Span<byte> b9 = blocks[^BlockSize..];

            Xor(b6, b0);
            Xor(b7, b1);
            Xor(b8, b0);
            Xor(b9, b1);

            Xor(commitment[..BlockSize], b6, b7);
            Xor(commitment[BlockSize..],b8, b9);
        }

        CryptographicOperations.ZeroMemory(blocks);
    }

    private static void Xor(Span<byte> destination, ReadOnlySpan<byte> source)
    {
        for (int i = 0; i < destination.Length; i++) {
            destination[i] ^= source[i];
        }
    }

    private static void Xor(Span<byte> destination, ReadOnlySpan<byte> source1, ReadOnlySpan<byte> source2)
    {
        for (int i = 0; i < destination.Length; i++) {
            destination[i] = (byte)(source1[i] ^ source2[i]);
        }
    }
}
