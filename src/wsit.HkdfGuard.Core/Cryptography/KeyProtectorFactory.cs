using wsit.HkdfGuard.Abstractions;

namespace wsit.HkdfGuard.Core.Cryptography;

public sealed class KeyProtectorFactory : IKeyProtectorFactory
{
    public IKeyProtector ForBootstrap(IKeySpec spec, byte[] salt)
        => new KeyProtector(spec.KeyDerivation, spec.Cipher, salt, spec.MaterialIdentifier, spec.Iterations, spec.ServiceName);
}
