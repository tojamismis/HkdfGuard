using System.Security.Cryptography;

namespace wsit.Hkdf.Cryptography;

public class AesGcmCipher : ISymmetricCipher, IDisposable
{
    private readonly AesGcm _aes;
    
    private const int TagSize = 16;
    private const int NonceSize = 12;
    
    

    public AesGcmCipher(ReadOnlySpan<byte> key)
    {
        if (key.Length != 32)
            throw new ArgumentException("AES key must be 256 bits.", nameof(key));

        _aes = new AesGcm(key, TagSize); // AesGcm requires a byte[]
    }

    public int Encrypt(Span<byte> plaintext, Span<byte> result)
        => Encrypt(plaintext, ReadOnlySpan<byte>.Empty, result);

    public int Encrypt(Span<byte> plaintext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        if (result.Length < NonceSize + plaintext.Length + TagSize)
            throw new ArgumentException("Result buffer too small.", nameof(result));

        // Layout: [nonce | ciphertext | tag]
        var nonce = result.Slice(0, NonceSize);
        var ciphertext = result.Slice(NonceSize, plaintext.Length);
        var tag = result.Slice(NonceSize + plaintext.Length, TagSize);

        RandomNumberGenerator.Fill(nonce);

        _aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        return NonceSize + plaintext.Length + TagSize;
    }

    public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result)
        => Decrypt(ciphertext, ReadOnlySpan<byte>.Empty, result);

    public int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        if (ciphertext.Length < NonceSize + TagSize)
            throw new ArgumentException("Ciphertext too short.", nameof(ciphertext));

        var resultLength = ciphertext.Length - NonceSize - TagSize;

        if (result.Length < resultLength)
            throw new ArgumentException("Result buffer too small.", nameof(result));

        var nonce = ciphertext.Slice(0, NonceSize);
        var ct = ciphertext.Slice(NonceSize, resultLength);
        var tag = ciphertext.Slice(NonceSize + resultLength, TagSize);

        _aes.Decrypt(nonce, ct, tag, result, aad);

        return resultLength;
    }

    public void Dispose()
    {
        _aes.Dispose();
    }
}
