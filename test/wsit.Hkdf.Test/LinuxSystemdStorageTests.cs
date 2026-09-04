using wsit.Hkdf.Interop;

namespace wsit.Hkdf.Test;

public class LinuxSystemdStorageTests
{
    [Fact]
    public void CreateOrGet_PersistsAndReturnsSameMaterial()
    {
        if (!OperatingSystem.IsLinux())
            return; // Backed by the Linux kernel keyring / systemd-creds; only exercised on Linux.

        var storage = new LinuxSystemdStorage();
        var index = $"wsit.Hkdf.Test.{Guid.NewGuid()}";

        var first = new byte[32];
        var second = new byte[32];

        var written = storage.CreateOrGet(index, first);
        storage.CreateOrGet(index, second);

        Assert.Equal(32, written);
        Assert.Equal(first, second);
    }
}
