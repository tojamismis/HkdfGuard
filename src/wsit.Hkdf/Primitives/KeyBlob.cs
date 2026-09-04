using System.Security.Cryptography;
using System.Text;
using wsit.Hkdf.Diagnostics;
using wsit.Hkdf.Utilities;

namespace wsit.Hkdf.Primitives;

public readonly ref struct KeyBlob
{
    public ReadOnlySpan<byte> Salt { get; }
    public ReadOnlySpan<byte> EncryptedKey { get; }
    public byte Iterations { get; }
    public byte MaterialIdentifier { get; }
    public ReadOnlySpan<byte> Signature { get; }

    public const int SaltLength = 64;
    public const int EncryptedKeyLength = 92;
    public const int SignatureLength = 32;
    public const int TotalLength = SaltLength + EncryptedKeyLength + 2 + SignatureLength;

    private KeyBlob(
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> encryptedKey,
        byte iterations,
        byte materialIdentifier,
        ReadOnlySpan<byte> signature)
    {
        Salt = salt;
        EncryptedKey = encryptedKey;
        Iterations = iterations;
        MaterialIdentifier = materialIdentifier;
        Signature = signature;
    }

    /// <summary>
    /// Parses and authenticates a serialized key blob
    /// </summary>
    /// <param name="data">The serialized blob bytes</param>
    /// <param name="keyDerivation">The KeyDerivationFunction used to derive the signing key</param>
    /// <param name="storage">The KeyInputStorageController object</param>
    /// <param name="hash">The IHash implementation used to verify the blob's signature</param>
    /// <param name="serviceName">The assigned name or prefix for this service in keyStorage</param>
    /// <param name="blob">The parsed blob, when successful</param>
    /// <returns>True if the blob was well-formed and its signature is valid</returns>
    public static bool TryLoad(
        ReadOnlySpan<byte> data,
        IKeyDerivationFunction keyDerivation,
        IKeyInputStorage storage,
        IHash hash,
        string serviceName,
        out KeyBlob blob)
    {
        using var activity = HkdfDiagnostics.ActivitySource.StartActivity("KeyBlob.TryLoad");
        if (HkdfDiagnostics.EnableSensitiveLogging)
            HkdfDiagnostics.LogSensitiveOperation(activity, "KeyBlob.TryLoad",
                ("serviceName", serviceName), ("dataLength", data.Length));

        if (data.Length != TotalLength)
        {
            blob = default;
            return false;
        }

        if (ArrayUtility.IsNullOrEmpty(data))
        {
            blob = default;
            return false;
        }

        var salt = data.Slice(0, SaltLength);
        var encKey = data.Slice(SaltLength, EncryptedKeyLength);
        byte iter = data[SaltLength + EncryptedKeyLength];
        byte mat = data[SaltLength + EncryptedKeyLength + 1];
        var signature = data.Slice(SaltLength + EncryptedKeyLength + 2, SignatureLength);

        var candidate = new KeyBlob(salt, encKey, iter, mat, signature);

        Span<byte> expectedSignature = stackalloc byte[SignatureLength];
        try
        {
            ComputeSignature(candidate, keyDerivation, storage, hash, serviceName, expectedSignature);

            if (!CryptographicOperations.FixedTimeEquals(expectedSignature, signature))
            {
                blob = default;
                return false;
            }

            blob = candidate;
            return true;
        }
        catch (Exception ex)
        {
            HkdfDiagnostics.RecordException(activity, ex);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedSignature);
        }
    }

    /// <summary>
    /// Builds and signs a serialized key blob
    /// </summary>
    /// <param name="destination">The span to receive the serialized blob</param>
    /// <param name="salt">The 64 byte salt</param>
    /// <param name="encryptedKey">The 92 byte encrypted key</param>
    /// <param name="iterationIndex">The iteration count index</param>
    /// <param name="materialIndex">The key material identifier</param>
    /// <param name="keyDerivation">The KeyDerivationFunction used to derive the signing key</param>
    /// <param name="storage">The KeyInputStorageController object</param>
    /// <param name="hash">The IHash implementation used to sign the blob</param>
    /// <param name="serviceName">The assigned name or prefix for this service in keyStorage</param>
    public static void Create(
        Span<byte> destination,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> encryptedKey,
        byte iterationIndex,
        byte materialIndex,
        IKeyDerivationFunction keyDerivation,
        IKeyInputStorage storage,
        IHash hash,
        string serviceName)
    {
        using var activity = HkdfDiagnostics.ActivitySource.StartActivity("KeyBlob.Create");
        if (HkdfDiagnostics.EnableSensitiveLogging)
            HkdfDiagnostics.LogSensitiveOperation(activity, "KeyBlob.Create",
                ("serviceName", serviceName), ("materialIndex", materialIndex), ("iterationIndex", iterationIndex));

        try
        {
            if (destination.Length < TotalLength)
                throw new ArgumentException("Destination buffer too small.", nameof(destination));

            if (salt.Length != SaltLength)
                throw new ArgumentException("Salt must be 64 bytes.", nameof(salt));

            if (encryptedKey.Length != EncryptedKeyLength)
                throw new ArgumentException("Encrypted key must be 92 bytes.", nameof(encryptedKey));

            if (ArrayUtility.IsNullOrEmpty(salt))
                throw new ArgumentException("Salt must not be all zero.", nameof(salt));

            if (ArrayUtility.IsNullOrEmpty(encryptedKey))
                throw new ArgumentException("Encrypted key must not be all zero.", nameof(encryptedKey));

            salt.CopyTo(destination.Slice(0, SaltLength));
            encryptedKey.CopyTo(destination.Slice(SaltLength, EncryptedKeyLength));
            destination[SaltLength + EncryptedKeyLength] = iterationIndex;
            destination[SaltLength + EncryptedKeyLength + 1] = materialIndex;

            var signatureDestination = destination.Slice(SaltLength + EncryptedKeyLength + 2, SignatureLength);
            var candidate = new KeyBlob(
                destination.Slice(0, SaltLength),
                destination.Slice(SaltLength, EncryptedKeyLength),
                iterationIndex,
                materialIndex,
                signatureDestination);

            ComputeSignature(candidate, keyDerivation, storage, hash, serviceName, signatureDestination);
        }
        catch (Exception ex)
        {
            HkdfDiagnostics.RecordException(activity, ex);
            throw;
        }
    }

    // Signs Salt + Iterations + MaterialIdentifier + HostName, binding the blob's header to the
    // machine that created it so a blob copied elsewhere fails authentication.
    private static void ComputeSignature(
        KeyBlob blob,
        IKeyDerivationFunction keyDerivation,
        IKeyInputStorage storage,
        IHash hash,
        string serviceName,
        Span<byte> result)
    {
        var hostName = Environment.MachineName;
        Span<byte> hostNameBytes = stackalloc byte[Encoding.UTF8.GetByteCount(hostName)];
        Encoding.UTF8.GetBytes(hostName, hostNameBytes);

        Span<byte> signingKey = stackalloc byte[32];
        Span<byte> message = stackalloc byte[blob.Salt.Length + 2 + hostNameBytes.Length];
        try
        {
            keyDerivation.Derive(blob.Salt, blob, storage, serviceName, signingKey);

            blob.Salt.CopyTo(message);
            message[blob.Salt.Length] = blob.Iterations;
            message[blob.Salt.Length + 1] = blob.MaterialIdentifier;
            hostNameBytes.CopyTo(message[(blob.Salt.Length + 2)..]);

            hash.ComputeHash(signingKey, message, result);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signingKey);
        }
    }
}
