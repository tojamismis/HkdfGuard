namespace wsit.Hkdf.Primitives;

public readonly ref struct KeyBlob
{
    public ReadOnlySpan<byte> Salt { get; }
    public ReadOnlySpan<byte> EncryptedKey { get; }
    public byte Iterations { get; }
    public byte MaterialIdentifier { get; }

    public const int SaltLength = 64;
    public const int EncryptedKeyLength = 60;
    public const int TotalLength = SaltLength + EncryptedKeyLength + 2;

    private KeyBlob(
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> encryptedKey,
        byte iterations,
        byte materialIdentifier)
    {
        Salt = salt;
        EncryptedKey = encryptedKey;
        Iterations = iterations;
        MaterialIdentifier = materialIdentifier;
    }

    public static bool TryParse(ReadOnlySpan<byte> data, out KeyBlob blob)
    {
        if (data.Length != TotalLength)
        {
            blob = default;
            return false;
        }

        var salt = data.Slice(0, SaltLength);
        var encKey = data.Slice(SaltLength, EncryptedKeyLength);
        byte iter = data[SaltLength + EncryptedKeyLength];
        byte mat = data[SaltLength + EncryptedKeyLength + 1];

        blob = new KeyBlob(salt, encKey, iter, mat);
        return true;
    }

    public static void WriteTo(
        Span<byte> destination,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> encryptedKey,
        byte iterationIndex,
        byte materialIndex)
    {
        if (destination.Length < TotalLength)
            throw new ArgumentException("Destination buffer too small.", nameof(destination));

        if (salt.Length != SaltLength)
            throw new ArgumentException("Salt must be 64 bytes.", nameof(salt));

        if (encryptedKey.Length != EncryptedKeyLength)
            throw new ArgumentException("Encrypted key must be 60 bytes.", nameof(encryptedKey));

        salt.CopyTo(destination.Slice(0, SaltLength));
        encryptedKey.CopyTo(destination.Slice(SaltLength, EncryptedKeyLength));
        destination[SaltLength + EncryptedKeyLength] = iterationIndex;
        destination[SaltLength + EncryptedKeyLength + 1] = materialIndex;
    }
}