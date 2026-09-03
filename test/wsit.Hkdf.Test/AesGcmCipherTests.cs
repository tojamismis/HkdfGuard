using System.Security.Cryptography;
using wsit.Hkdf.Cryptography;

namespace wsit.Hkdf.Test;

public class AesGcmCipherTests
{
    [Fact]
    public void Constructor_RejectsNonStandardKeyLength()
    {
        Assert.Throws<ArgumentException>(() => new AesGcmCipher(new byte[16]));
    }

    [Fact]
    public void EncryptDecrypt_RoundTrips()
    {
        using var cipher = new AesGcmCipher(RandomNumberGenerator.GetBytes(32));
        var plaintext = "hello world"u8.ToArray();
        var encrypted = new byte[plaintext.Length + 28];

        var written = cipher.Encrypt(plaintext, encrypted);
        Assert.Equal(encrypted.Length, written);

        var decrypted = new byte[plaintext.Length];
        var decryptedLength = cipher.Decrypt(encrypted, decrypted);

        Assert.Equal(plaintext.Length, decryptedLength);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_RoundTrips_WithAad()
    {
        using var cipher = new AesGcmCipher(RandomNumberGenerator.GetBytes(32));
        var plaintext = "hello world"u8.ToArray();
        var aad = "context"u8.ToArray();
        var encrypted = new byte[plaintext.Length + 28];

        cipher.Encrypt(plaintext, aad, encrypted);

        var decrypted = new byte[plaintext.Length];
        cipher.Decrypt(encrypted, aad, decrypted);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Decrypt_WithWrongAad_Throws()
    {
        using var cipher = new AesGcmCipher(RandomNumberGenerator.GetBytes(32));
        var plaintext = "hello world"u8.ToArray();
        var encrypted = new byte[plaintext.Length + 28];
        cipher.Encrypt(plaintext, "correct-aad"u8.ToArray(), encrypted);

        var decrypted = new byte[plaintext.Length];
        Assert.Throws<AuthenticationTagMismatchException>(() =>
            cipher.Decrypt(encrypted, "wrong-aad"u8.ToArray(), decrypted));
    }

    [Fact]
    public void Decrypt_WithTamperedCiphertext_Throws()
    {
        using var cipher = new AesGcmCipher(RandomNumberGenerator.GetBytes(32));
        var plaintext = "hello world"u8.ToArray();
        var encrypted = new byte[plaintext.Length + 28];
        cipher.Encrypt(plaintext, encrypted);
        encrypted[15] ^= 0xFF;

        var decrypted = new byte[plaintext.Length];
        Assert.Throws<AuthenticationTagMismatchException>(() => cipher.Decrypt(encrypted, decrypted));
    }

    [Fact]
    public void Encrypt_WithTooSmallResultBuffer_Throws()
    {
        using var cipher = new AesGcmCipher(RandomNumberGenerator.GetBytes(32));
        var plaintext = "hello world"u8.ToArray();
        var tooSmall = new byte[plaintext.Length];

        Assert.Throws<ArgumentException>(() => cipher.Encrypt(plaintext, tooSmall));
    }

    [Fact]
    public void Decrypt_WithTooShortCiphertext_Throws()
    {
        using var cipher = new AesGcmCipher(RandomNumberGenerator.GetBytes(32));
        var tooShort = new byte[10];
        var result = new byte[4];

        Assert.Throws<ArgumentException>(() => cipher.Decrypt(tooShort, result));
    }
}
