using System.Security.Cryptography;
using wsit.Hkdf.Cryptography;
using wsit.Hkdf.Primitives;
using wsit.Hkdf.Test.TestHelpers;

namespace wsit.Hkdf.Test;

public class HkdfKeyWrapperTests
{
    private const string ServiceName = "svc";

    private static byte[] CreateProtectedKeyBlob(IKeyDerivationFunction keyDerivation, IKeyInputStorage storage, IHash hash)
    {
        var salt = RandomNumberGenerator.GetBytes(KeyBlob.SaltLength);
        var encryptedKey = RandomNumberGenerator.GetBytes(KeyBlob.EncryptedKeyLength);
        var buffer = new byte[KeyBlob.TotalLength];

        KeyBlob.Create(buffer, salt, encryptedKey, 1, 1, keyDerivation, storage, hash, ServiceName);
        return buffer;
    }

    [Fact]
    public void EncryptDecrypt_RoundTrips()
    {
        var keyDerivation = new Pbkdf2KeyDerivationFunction();
        var storage = new InMemoryKeyInputStorage();
        var hash = new HmacSha256Hash();
        var cipher = new AesGcmCipher();
        var rawKey = CreateProtectedKeyBlob(keyDerivation, storage, hash);
        var wrapper = new HkdfKeyWrapper(keyDerivation, storage, cipher, hash, rawKey, ServiceName);

        var plaintext = "top secret"u8.ToArray();
        // AesGcmCipher.Encrypt zeroes the plaintext span it's given as a side effect, so snapshot it first.
        var expectedPlaintext = (byte[])plaintext.Clone();
        var encrypted = new byte[plaintext.Length + 60];

        var written = wrapper.Encrypt(plaintext, encrypted);
        Assert.Equal(encrypted.Length, written);

        var decrypted = new byte[expectedPlaintext.Length];
        var decryptedLength = wrapper.Decrypt(encrypted, decrypted);

        Assert.Equal(expectedPlaintext.Length, decryptedLength);
        Assert.Equal(expectedPlaintext, decrypted);
    }

    [Fact]
    public void Encrypt_WithInvalidProtectedKey_Throws()
    {
        var keyDerivation = new Pbkdf2KeyDerivationFunction();
        var storage = new InMemoryKeyInputStorage();
        var hash = new HmacSha256Hash();
        var cipher = new AesGcmCipher();
        var wrapper = new HkdfKeyWrapper(keyDerivation, storage, cipher, hash, new byte[10], ServiceName);

        var plaintext = "top secret"u8.ToArray();
        var encrypted = new byte[plaintext.Length + 60];

        Assert.Throws<CryptographicException>(() => wrapper.Encrypt(plaintext, encrypted));
    }

    [Fact]
    public void Decrypt_WithInvalidProtectedKey_Throws()
    {
        var keyDerivation = new Pbkdf2KeyDerivationFunction();
        var storage = new InMemoryKeyInputStorage();
        var hash = new HmacSha256Hash();
        var cipher = new AesGcmCipher();
        var wrapper = new HkdfKeyWrapper(keyDerivation, storage, cipher, hash, new byte[10], ServiceName);

        var ciphertext = RandomNumberGenerator.GetBytes(70);
        var result = new byte[10];

        Assert.Throws<CryptographicException>(() => wrapper.Decrypt(ciphertext, result));
    }
}
