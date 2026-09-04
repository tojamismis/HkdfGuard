using wsit.DataProtectionKey.Diagnostics;
using wsit.DataProtectionKey.Interface;
using wsit.Hkdf;

namespace wsit.DataProtectionKey.Key;

public class KeyWrappedDataProtectionKey(IKeyWrapper wrapper) : IDataProtectionKey
{
    /// <inheritdoc/>
    public int Encrypt(Span<byte> plaintext, Span<byte> result)
    {
        using var activity = DataProtectionDiagnostics.ActivitySource.StartActivity("KeyWrappedDataProtectionKey.Encrypt");
        if (DataProtectionDiagnostics.EnableSensitiveLogging)
            DataProtectionDiagnostics.LogSensitiveOperation(activity, "KeyWrappedDataProtectionKey.Encrypt",
                ("plaintextLength", plaintext.Length));

        try
        {
            throw new NotImplementedException();
        }
        catch (Exception ex)
        {
            DataProtectionDiagnostics.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public int Encrypt(Span<byte> plaintext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        using var activity = DataProtectionDiagnostics.ActivitySource.StartActivity("KeyWrappedDataProtectionKey.Encrypt");
        if (DataProtectionDiagnostics.EnableSensitiveLogging)
            DataProtectionDiagnostics.LogSensitiveOperation(activity, "KeyWrappedDataProtectionKey.Encrypt",
                ("plaintextLength", plaintext.Length), ("aadLength", aad.Length));

        try
        {
            throw new NotImplementedException();
        }
        catch (Exception ex)
        {
            DataProtectionDiagnostics.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result)
    {
        using var activity = DataProtectionDiagnostics.ActivitySource.StartActivity("KeyWrappedDataProtectionKey.Decrypt");
        if (DataProtectionDiagnostics.EnableSensitiveLogging)
            DataProtectionDiagnostics.LogSensitiveOperation(activity, "KeyWrappedDataProtectionKey.Decrypt",
                ("ciphertextLength", ciphertext.Length));

        try
        {
            throw new NotImplementedException();
        }
        catch (Exception ex)
        {
            DataProtectionDiagnostics.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        using var activity = DataProtectionDiagnostics.ActivitySource.StartActivity("KeyWrappedDataProtectionKey.Decrypt");
        if (DataProtectionDiagnostics.EnableSensitiveLogging)
            DataProtectionDiagnostics.LogSensitiveOperation(activity, "KeyWrappedDataProtectionKey.Decrypt",
                ("ciphertextLength", ciphertext.Length), ("aadLength", aad.Length));

        try
        {
            throw new NotImplementedException();
        }
        catch (Exception ex)
        {
            DataProtectionDiagnostics.RecordException(activity, ex);
            throw;
        }
    }
}