using System.Security.Cryptography;

namespace wsit.Hkdf.Cryptography;

public class HmacSha256Hash : IHash
{
    public const int HashSize = 32;

    public int ComputeHash(ReadOnlySpan<byte> key, Span<byte> data, Span<byte> result)
        => HMACSHA256.HashData(key, data, result);
}
