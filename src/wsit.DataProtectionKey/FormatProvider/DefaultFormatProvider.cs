using wsit.DataProtectionKey.Diagnostics;
using wsit.DataProtectionKey.Interface;
using wsit.DataProtectionKey.Primitives;
using wsit.DataProtectionKey.Utilities;

namespace wsit.DataProtectionKey.FormatProvider;

public class DefaultFormatProvider : IEncryptedFormatProvider
{
    private const string EncPrefix = "enc";
    private const string Delimiter = "::";
    private const string VersionPrefix = "v";

    public string Format(KeyTrackingValue value)
    {
        using var activity = DataProtectionDiagnostics.ActivitySource.StartActivity("DefaultFormatProvider.Format");
        if (DataProtectionDiagnostics.EnableSensitiveLogging)
            DataProtectionDiagnostics.LogSensitiveOperation(activity, "DefaultFormatProvider.Format",
                ("keyVersion", value.KeyVersion), ("valueLength", value.Value.Length));

        try
        {
            var base64 = Base64ConversionUtility.ToBase64String(value.Value);
            return $"{EncPrefix}{Delimiter}{VersionPrefix}{value.KeyVersion}{Delimiter}{base64}";
        }
        catch (Exception ex)
        {
            DataProtectionDiagnostics.RecordException(activity, ex);
            throw;
        }
    }

    public KeyTrackingValue Parse(string encrypted)
    {
        using var activity = DataProtectionDiagnostics.ActivitySource.StartActivity("DefaultFormatProvider.Parse");
        if (DataProtectionDiagnostics.EnableSensitiveLogging)
            DataProtectionDiagnostics.LogSensitiveOperation(activity, "DefaultFormatProvider.Parse",
                ("encryptedLength", encrypted.Length));

        try
        {
            var parts = encrypted.Split(Delimiter);
            if (parts.Length != 3 || parts[0] != EncPrefix || !parts[1].StartsWith(VersionPrefix))
                throw new FormatException($"Invalid encrypted format. Expected '{EncPrefix}{Delimiter}{VersionPrefix}<version>{Delimiter}<base64>'.");

            if (!int.TryParse(parts[1].AsSpan(VersionPrefix.Length), out var version))
                throw new FormatException($"Invalid key version in '{parts[1]}'.");

            var base64 = parts[2];
            if (!Base64ConversionUtility.IsBase64(base64))
                throw new FormatException("Encrypted value is not valid base64.");

            var value = new byte[Base64ConversionUtility.GetBinaryLength(base64)];
            Base64ConversionUtility.FromBase64(base64, value);

            return new KeyTrackingValue
            {
                KeyVersion = version,
                Value = value
            };
        }
        catch (Exception ex)
        {
            DataProtectionDiagnostics.RecordException(activity, ex);
            throw;
        }
    }
}