using wsit.DataProtectionKey.Primitives;

namespace wsit.DataProtectionKey.Interface;

public interface IEncryptedFormatProvider
{
    public string Format(KeyTrackingValue value);
    public KeyTrackingValue Parse(string encrypted);
}