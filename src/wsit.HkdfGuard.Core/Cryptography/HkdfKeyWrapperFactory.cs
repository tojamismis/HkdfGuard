using wsit.HkdfGuard.Abstractions;

namespace wsit.HkdfGuard.Core.Cryptography;

public sealed class HkdfKeyWrapperFactory : IKeyWrapperFactory
{
    public IKeyWrapper ForProtectedKey(IKeySpec spec, IKeyBlob blob)
        => new HkdfKeyWrapper(spec.KeyDerivation, spec.Cipher, blob, spec.MaterialIdentifier, spec.Iterations, spec.ServiceName);
}
