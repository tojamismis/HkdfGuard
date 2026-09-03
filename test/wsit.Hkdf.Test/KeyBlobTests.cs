using System.Security.Cryptography;
using wsit.Hkdf.Cryptography;
using wsit.Hkdf.Primitives;
using wsit.Hkdf.Test.TestHelpers;

namespace wsit.Hkdf.Test;

public class KeyBlobTests
{
    private const string ServiceName = "svc";

    private static (IKeyDerivationFunction KeyDerivation, IKeyInputStorage Storage, IHash Hash) CreateDependencies()
        => (new Pbkdf2KeyDerivationFunction(), new InMemoryKeyInputStorage(), new HmacSha256Hash());

    private static byte[] CreateValidBlob(IKeyDerivationFunction keyDerivation, IKeyInputStorage storage, IHash hash, byte iterations = 1, byte materialIdentifier = 1)
    {
        var salt = RandomNumberGenerator.GetBytes(KeyBlob.SaltLength);
        var encryptedKey = RandomNumberGenerator.GetBytes(KeyBlob.EncryptedKeyLength);
        var buffer = new byte[KeyBlob.TotalLength];

        KeyBlob.Create(buffer, salt, encryptedKey, iterations, materialIdentifier, keyDerivation, storage, hash, ServiceName);
        return buffer;
    }

    [Fact]
    public void CreateThenTryLoad_RoundTrips()
    {
        var (keyDerivation, storage, hash) = CreateDependencies();
        var salt = RandomNumberGenerator.GetBytes(KeyBlob.SaltLength);
        var encryptedKey = RandomNumberGenerator.GetBytes(KeyBlob.EncryptedKeyLength);
        var buffer = new byte[KeyBlob.TotalLength];

        KeyBlob.Create(buffer, salt, encryptedKey, 3, 7, keyDerivation, storage, hash, ServiceName);

        Assert.True(KeyBlob.TryLoad(buffer, keyDerivation, storage, hash, ServiceName, out var blob));
        Assert.Equal(salt, blob.Salt.ToArray());
        Assert.Equal(encryptedKey, blob.EncryptedKey.ToArray());
        Assert.Equal((byte)3, blob.Iterations);
        Assert.Equal((byte)7, blob.MaterialIdentifier);
        Assert.Equal(KeyBlob.SignatureLength, blob.Signature.Length);
    }

    [Fact]
    public void TryLoad_WithWrongLength_Fails()
    {
        var (keyDerivation, storage, hash) = CreateDependencies();

        Assert.False(KeyBlob.TryLoad(new byte[10], keyDerivation, storage, hash, ServiceName, out _));
    }

    [Fact]
    public void TryLoad_WithTamperedSalt_Fails()
    {
        var (keyDerivation, storage, hash) = CreateDependencies();
        var buffer = CreateValidBlob(keyDerivation, storage, hash);

        buffer[0] ^= 0xFF;

        Assert.False(KeyBlob.TryLoad(buffer, keyDerivation, storage, hash, ServiceName, out _));
    }

    [Fact]
    public void TryLoad_WithTamperedIterations_Fails()
    {
        var (keyDerivation, storage, hash) = CreateDependencies();
        var buffer = CreateValidBlob(keyDerivation, storage, hash);

        buffer[KeyBlob.SaltLength + KeyBlob.EncryptedKeyLength] ^= 0xFF;

        Assert.False(KeyBlob.TryLoad(buffer, keyDerivation, storage, hash, ServiceName, out _));
    }

    [Fact]
    public void TryLoad_WithTamperedMaterialIdentifier_Fails()
    {
        var (keyDerivation, storage, hash) = CreateDependencies();
        var buffer = CreateValidBlob(keyDerivation, storage, hash);

        buffer[KeyBlob.SaltLength + KeyBlob.EncryptedKeyLength + 1] ^= 0xFF;

        Assert.False(KeyBlob.TryLoad(buffer, keyDerivation, storage, hash, ServiceName, out _));
    }

    [Fact]
    public void TryLoad_WithTamperedSignature_Fails()
    {
        var (keyDerivation, storage, hash) = CreateDependencies();
        var buffer = CreateValidBlob(keyDerivation, storage, hash);

        buffer[^1] ^= 0xFF;

        Assert.False(KeyBlob.TryLoad(buffer, keyDerivation, storage, hash, ServiceName, out _));
    }

    [Fact]
    public void TryLoad_WithTamperedEncryptedKey_SignatureStillValid()
    {
        // The signature covers Salt + Iterations + MaterialIdentifier + HostName only,
        // so the encrypted key payload itself is not authenticated by KeyBlob.
        var (keyDerivation, storage, hash) = CreateDependencies();
        var buffer = CreateValidBlob(keyDerivation, storage, hash);

        buffer[KeyBlob.SaltLength] ^= 0xFF;

        Assert.True(KeyBlob.TryLoad(buffer, keyDerivation, storage, hash, ServiceName, out _));
    }

    [Fact]
    public void TryLoad_WithDifferentServiceName_Fails()
    {
        var (keyDerivation, storage, hash) = CreateDependencies();
        var buffer = CreateValidBlob(keyDerivation, storage, hash);

        Assert.False(KeyBlob.TryLoad(buffer, keyDerivation, storage, hash, "other-service", out _));
    }

    [Fact]
    public void Create_WithWrongSaltLength_Throws()
    {
        var (keyDerivation, storage, hash) = CreateDependencies();
        var buffer = new byte[KeyBlob.TotalLength];

        Assert.Throws<ArgumentException>(() =>
            KeyBlob.Create(buffer, new byte[10], new byte[KeyBlob.EncryptedKeyLength], 1, 1, keyDerivation, storage, hash, ServiceName));
    }

    [Fact]
    public void Create_WithWrongEncryptedKeyLength_Throws()
    {
        var (keyDerivation, storage, hash) = CreateDependencies();
        var buffer = new byte[KeyBlob.TotalLength];

        Assert.Throws<ArgumentException>(() =>
            KeyBlob.Create(buffer, new byte[KeyBlob.SaltLength], new byte[10], 1, 1, keyDerivation, storage, hash, ServiceName));
    }

    [Fact]
    public void Create_WithTooSmallDestination_Throws()
    {
        var (keyDerivation, storage, hash) = CreateDependencies();
        var buffer = new byte[KeyBlob.TotalLength - 1];

        Assert.Throws<ArgumentException>(() =>
            KeyBlob.Create(buffer, new byte[KeyBlob.SaltLength], new byte[KeyBlob.EncryptedKeyLength], 1, 1, keyDerivation, storage, hash, ServiceName));
    }
}
