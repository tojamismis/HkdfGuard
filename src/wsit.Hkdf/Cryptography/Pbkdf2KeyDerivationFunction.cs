using System.Security.Cryptography;
using System.Text.Json.Serialization;
using wsit.Hkdf.Diagnostics;
using wsit.Hkdf.Primitives;
using wsit.Hkdf.Utilities;

namespace wsit.Hkdf.Cryptography;

public class Pbkdf2KeyDerivationFunction : IKeyDerivationFunction
{
    public int Derive(ReadOnlySpan<byte> uniqueBytes, KeyBlob blob, IKeyInputStorage storage, string serviceName,
        scoped Span<byte> result)
    {
        using var activity = HkdfDiagnostics.ActivitySource.StartActivity("Pbkdf2KeyDerivationFunction.Derive");
        if (HkdfDiagnostics.EnableSensitiveLogging)
            HkdfDiagnostics.LogSensitiveOperation(activity, "Pbkdf2KeyDerivationFunction.Derive",
                ("serviceName", serviceName), ("materialIdentifier", blob.MaterialIdentifier), ("iterations", blob.Iterations));

        Span<byte> keyMaterial = stackalloc byte[32];
        Span<byte> saltBytes = stackalloc byte[uniqueBytes.Length + blob.Salt.Length];
        try
        {
            if (ArrayUtility.IsNullOrEmpty(uniqueBytes))
                throw new ArgumentException("Unique bytes must not be empty or all zero.", nameof(uniqueBytes));

            uniqueBytes.CopyTo(saltBytes.Slice(0, uniqueBytes.Length));
            blob.Salt.CopyTo(saltBytes.Slice(uniqueBytes.Length, blob.Salt.Length));
            var index = $"{serviceName}.{blob.MaterialIdentifier}";
            storage.CreateOrGet(index, keyMaterial);
            return DeriveCore(keyMaterial, saltBytes, blob.Iterations, result);
        }
        catch (Exception ex)
        {
            HkdfDiagnostics.RecordException(activity, ex);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyMaterial);
            CryptographicOperations.ZeroMemory(saltBytes);
        }
    }

    //The actual derivation requires a static set of keyMaterial during the 
    private int DeriveCore(ReadOnlySpan<byte> keyMaterial, ReadOnlySpan<byte> salt, 
        int iterations, scoped Span<byte> result)
    {
        Rfc2898DeriveBytes.Pbkdf2(keyMaterial, salt, result, iterations, HashAlgorithmName.SHA256);
        return result.Length;
    }
}