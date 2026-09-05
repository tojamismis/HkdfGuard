using System.Diagnostics;
using wsit.HkdfGuard.Core.Diagnostics;

namespace wsit.HkdfGuard.DataProtectionKey.Diagnostics;

public static class DataProtectionDiagnostics
{
    public const string SourceName = "wsit.HkdfGuard.DataProtectionKey";

    public static readonly ActivitySource ActivitySource = new(SourceName);

    /// <summary>
    /// Shared with <see cref="HkdfDiagnostics.EnableSensitiveLogging"/> - one flag controls
    /// sensitive-operation debug logging across both the wsit.HkdfGuard.Core and wsit.HkdfGuard.DataProtectionKey libraries.
    /// </summary>
    public static bool EnableSensitiveLogging
    {
        get => HkdfDiagnostics.EnableSensitiveLogging;
        set => HkdfDiagnostics.EnableSensitiveLogging = value;
    }

    public static void RecordException(Activity? activity, Exception exception)
        => HkdfDiagnostics.RecordException(activity, exception);

    public static void LogSensitiveOperation(Activity? activity, string operationName, params (string Key, object? Value)[] details)
        => HkdfDiagnostics.LogSensitiveOperation(activity, operationName, details);
}
