using System.Security.Cryptography;
using wsit.Hkdf.Cryptography;
using wsit.Hkdf.Primitives;
using wsit.Hkdf.Test.TestHelpers;

namespace wsit.Hkdf.Test;

public class Pbkdf2KeyDerivationFunctionTests
{
    private const string ServiceName = "svc";

    private static byte[] CreateSignedBlob(IKeyDerivationFunction keyDerivation, IKeyInputStorage storage, IHash hash)
    {
        var salt = RandomNumberGenerator.GetBytes(KeyBlob.SaltLength);
        var encryptedKey = RandomNumberGenerator.GetBytes(KeyBlob.EncryptedKeyLength);
        var buffer = new byte[KeyBlob.TotalLength];

        KeyBlob.Create(buffer, salt, encryptedKey, 1, 1, keyDerivation, storage, hash, ServiceName);
        return buffer;
    }

    [Fact]
    public void Derive_WritesRequestedLength()
    {
        var keyDerivation = new Pbkdf2KeyDerivationFunction();
        var storage = new InMemoryKeyInputStorage();
        var hash = new HmacSha256Hash();
        var blobBytes = CreateSignedBlob(keyDerivation, storage, hash);
        Assert.True(KeyBlob.TryLoad(blobBytes, keyDerivation, storage, hash, ServiceName, out var blob));

        var result = new byte[32];
        var written = keyDerivation.Derive(RandomNumberGenerator.GetBytes(16), blob, storage, ServiceName, result);

        Assert.Equal(32, written);
    }

    [Fact]
    public void Derive_IsDeterministicForSameInputs()
    {
        var keyDerivation = new Pbkdf2KeyDerivationFunction();
        var storage = new InMemoryKeyInputStorage();
        var hash = new HmacSha256Hash();
        var blobBytes = CreateSignedBlob(keyDerivation, storage, hash);
        Assert.True(KeyBlob.TryLoad(blobBytes, keyDerivation, storage, hash, ServiceName, out var blob));

        var uniqueBytes = RandomNumberGenerator.GetBytes(16);
        var first = new byte[32];
        var second = new byte[32];

        keyDerivation.Derive(uniqueBytes, blob, storage, ServiceName, first);
        keyDerivation.Derive(uniqueBytes, blob, storage, ServiceName, second);

        Assert.Equal(first, second);
    }

    [Fact]
    public void Derive_DifferentUniqueBytes_ProduceDifferentKeys()
    {
        var keyDerivation = new Pbkdf2KeyDerivationFunction();
        var storage = new InMemoryKeyInputStorage();
        var hash = new HmacSha256Hash();
        var blobBytes = CreateSignedBlob(keyDerivation, storage, hash);
        Assert.True(KeyBlob.TryLoad(blobBytes, keyDerivation, storage, hash, ServiceName, out var blob));

        var first = new byte[32];
        var second = new byte[32];

        keyDerivation.Derive(RandomNumberGenerator.GetBytes(16), blob, storage, ServiceName, first);
        keyDerivation.Derive(RandomNumberGenerator.GetBytes(16), blob, storage, ServiceName, second);

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void Derive_DifferentServiceName_ProducesDifferentKeys()
    {
        var keyDerivation = new Pbkdf2KeyDerivationFunction();
        var storage = new InMemoryKeyInputStorage();
        var hash = new HmacSha256Hash();
        var blobBytes = CreateSignedBlob(keyDerivation, storage, hash);
        Assert.True(KeyBlob.TryLoad(blobBytes, keyDerivation, storage, hash, ServiceName, out var blob));

        var uniqueBytes = RandomNumberGenerator.GetBytes(16);
        var first = new byte[32];
        var second = new byte[32];

        keyDerivation.Derive(uniqueBytes, blob, storage, ServiceName, first);
        keyDerivation.Derive(uniqueBytes, blob, storage, "other-service", second);

        Assert.NotEqual(first, second);
    }
}
