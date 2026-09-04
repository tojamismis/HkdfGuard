using System.Security.Cryptography;
using wsit.Hkdf.Diagnostics;
using wsit.Hkdf.Primitives;
using wsit.Hkdf.Utilities;

namespace wsit.Hkdf.Cryptography;

public class HkdfKeyWrapper(IKeyDerivationFunction keyDerivation, 
    IKeyInputStorage keyStorage, 
    ISymmetricCipher cipher, 
    IHash hash, 
    byte[] rawKey, 
    string serviceName)
 : IKeyWrapper
{
    public int Encrypt(Span<byte> plaintext, Span<byte> result)
        => Encrypt(plaintext, ReadOnlySpan<byte>.Empty, result);

    public int Encrypt(Span<byte> plaintext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        using var activity = HkdfDiagnostics.ActivitySource.StartActivity("HkdfKeyWrapper.Encrypt");
        if (HkdfDiagnostics.EnableSensitiveLogging)
            HkdfDiagnostics.LogSensitiveOperation(activity, "HkdfKeyWrapper.Encrypt",
                ("serviceName", serviceName), ("plaintextLength", plaintext.Length), ("aadLength", aad.Length));

        Span<byte> key = stackalloc byte[32];
        try
        {
            if (ArrayUtility.IsNullOrEmpty(plaintext))
                throw new ArgumentException("Plaintext must not be empty or all zero.", nameof(plaintext));

            if(!KeyBlob.TryLoad(rawKey, keyDerivation, keyStorage, hash, serviceName, out var blob))
                throw new CryptographicException("Invalid protected key format");

            var nonce = result.Slice(0, 32);
            RandomNumberGenerator.Fill(nonce);
            keyDerivation.Derive(nonce, blob, keyStorage, serviceName, key);
            return cipher.Encrypt(key, plaintext, result.Slice(32, result.Length - 32)) + 32;
        }
        catch (Exception ex)
        {
            HkdfDiagnostics.RecordException(activity, ex);
            throw;
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
        using var activity = HkdfDiagnostics.ActivitySource.StartActivity("HkdfKeyWrapper.Decrypt");
        if (HkdfDiagnostics.EnableSensitiveLogging)
            HkdfDiagnostics.LogSensitiveOperation(activity, "HkdfKeyWrapper.Decrypt",
                ("serviceName", serviceName), ("ciphertextLength", ciphertext.Length), ("aadLength", aad.Length));

        Span<byte> key = stackalloc byte[32];
        try
        {
            if (ArrayUtility.IsNullOrEmpty(ciphertext))
                throw new ArgumentException("Ciphertext must not be empty or all zero.", nameof(ciphertext));

            if(!KeyBlob.TryLoad(rawKey, keyDerivation, keyStorage, hash, serviceName, out var blob))
                throw new CryptographicException("Invalid protected key format");

            var nonce = ciphertext.Slice(0, 32);
            keyDerivation.Derive(nonce, blob, keyStorage, serviceName, key);
            return cipher.Decrypt(key, ciphertext.Slice(32, ciphertext.Length - 32), result);
        }
        catch (Exception ex)
        {
            HkdfDiagnostics.RecordException(activity, ex);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }
}