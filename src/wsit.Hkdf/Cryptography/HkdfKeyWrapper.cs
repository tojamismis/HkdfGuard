using System.Security.Cryptography;
using wsit.Hkdf.Primitives;

namespace wsit.Hkdf.Cryptography;

public class HkdfKeyWrapper(IKeyDerivationFunction keyDerivation, IKeyInputStorage keyStorage, ISymmetricCipher cipher, IHash hash, byte[] rawKey, string serviceName) : IKeyWrapper
{
    public int Encrypt(Span<byte> plaintext, Span<byte> result)
        => Encrypt(plaintext, ReadOnlySpan<byte>.Empty, result);

    public int Encrypt(Span<byte> plaintext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        Span<byte> key = stackalloc byte[32];
        try
        {
            if(!KeyBlob.TryLoad(rawKey, keyDerivation, keyStorage, hash, serviceName, out var blob))
                throw new CryptographicException("Invalid protected key format");

            var nonce = result.Slice(0, 32);
            RandomNumberGenerator.Fill(nonce);
            keyDerivation.Derive(nonce, blob, keyStorage, serviceName, key);
            return cipher.Encrypt(plaintext, result.Slice(32, result.Length - 32)) + 32;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result)
        => Decrypt(ciphertext, ReadOnlySpan<byte>.Empty, result);

    public int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        Span<byte> key = stackalloc byte[32];
        try
        {
            if(!KeyBlob.TryLoad(rawKey, keyDerivation, keyStorage, hash, serviceName, out var blob))
                throw new CryptographicException("Invalid protected key format");

            var nonce = ciphertext.Slice(0, 32);
            keyDerivation.Derive(nonce, blob, keyStorage, serviceName, key);
            return cipher.Decrypt(ciphertext.Slice(32, ciphertext.Length - 32), result);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }
}