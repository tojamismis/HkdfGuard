using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace wsit.Hkdf.Interop;

internal class MacKeyChainStorage : IKeyInputStorage
{
    private const string SecurityFramework = "/System/Library/Frameworks/Security.framework/Security";
    private const string CoreFoundation = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";

    private readonly string _service;

    public int CreateOrGet(string index, scoped Span<byte> material)
    {
        if(TryLoad(index, material))
            return material.Length;
        Generate(index);
        if(TryLoad(index, material))
            return material.Length;
        return 0;
    }

    private void Generate(string index)
    {
        if (string.IsNullOrEmpty(index))
            throw new ArgumentNullException(nameof(index));

        Span<byte> keyMaterial = stackalloc byte[32];
        RandomNumberGenerator.Fill(keyMaterial);
        using var dict = BuildAddDictionary(_service, index, keyMaterial);

        int status = SecItemAdd(dict.Handle, out _);
        if (status != 0)
            throw new Exception($"SecItemAdd failed: {status}");
    }

    private bool TryLoad(string index, scoped Span<byte> destination)
    {
        if (destination.Length != 32)
            throw new ArgumentException("Destination must be 32 bytes.");

        using var query = BuildQueryDictionary(_service, index);

        int status = SecItemCopyMatching(query.Handle, out IntPtr result);
        if (status != 0 || result == IntPtr.Zero)
            return false;

        try
        {
            ReadCFData(result, destination);
            return true;
        }
        finally
        {
            CFRelease(result);
        }
    }

    public void Delete(byte index)
    {
        string account = $"key-{index}";
        using var query = BuildDeleteDictionary(_service, account);

        SecItemDelete(query.Handle);
    }

    public void Dispose()
    {
        // Nothing persistent to dispose; CF objects are wrapped individually.
    }

    // ---------------- CF Helpers ----------------

    private static CFDictionary BuildAddDictionary(string service, string account, ReadOnlySpan<byte> data)
    {
        IntPtr cfService = CFStringCreate(service);
        IntPtr cfAccount = CFStringCreate(account);
        IntPtr cfData = CFDataCreate(data);

        IntPtr[] keys =
        {
            Sec.kSecClass,
            Sec.kSecAttrService,
            Sec.kSecAttrAccount,
            Sec.kSecValueData
        };

        IntPtr[] values =
        {
            Sec.kSecClassGenericPassword,
            cfService,
            cfAccount,
            cfData
        };

        return new CFDictionary(keys, values);
    }

    private static CFDictionary BuildQueryDictionary(string service, string account)
    {
        IntPtr cfService = CFStringCreate(service);
        IntPtr cfAccount = CFStringCreate(account);

        IntPtr[] keys =
        {
            Sec.kSecClass,
            Sec.kSecAttrService,
            Sec.kSecAttrAccount,
            Sec.kSecReturnData
        };

        IntPtr[] values =
        {
            Sec.kSecClassGenericPassword,
            cfService,
            cfAccount,
            new IntPtr(1)
        };

        return new CFDictionary(keys, values);
    }

    private static CFDictionary BuildDeleteDictionary(string service, string account)
    {
        IntPtr cfService = CFStringCreate(service);
        IntPtr cfAccount = CFStringCreate(account);

        IntPtr[] keys =
        {
            Sec.kSecClass,
            Sec.kSecAttrService,
            Sec.kSecAttrAccount
        };

        IntPtr[] values =
        {
            Sec.kSecClassGenericPassword,
            cfService,
            cfAccount
        };

        return new CFDictionary(keys, values);
    }

    private static void ReadCFData(IntPtr cfData, Span<byte> dest)
    {
        nint len = CFDataGetLength(cfData);
        if (len != 32)
            throw new Exception("Keychain item is not 32 bytes.");

        IntPtr ptr = CFDataGetBytePtr(cfData);
        Marshal.Copy(ptr, dest.ToArray(), 0, 32);
    }

    // ---------------- Native Imports ----------------

    [DllImport(SecurityFramework)]
    private static extern int SecItemAdd(IntPtr attributes, out IntPtr result);

    [DllImport(SecurityFramework)]
    private static extern int SecItemCopyMatching(IntPtr query, out IntPtr result);

    [DllImport(SecurityFramework)]
    private static extern int SecItemDelete(IntPtr query);

    [DllImport(CoreFoundation)]
    private static extern void CFRelease(IntPtr cfRef);

    [DllImport(CoreFoundation)]
    private static extern IntPtr CFStringCreateWithCString(IntPtr alloc, string str, uint encoding);

    [DllImport(CoreFoundation)]
    private static extern IntPtr CFDataCreate(IntPtr allocator, byte[] bytes, int length);

    [DllImport(CoreFoundation)]
    private static extern nint CFDataGetLength(IntPtr cfData);

    [DllImport(CoreFoundation)]
    private static extern IntPtr CFDataGetBytePtr(IntPtr cfData);

    private static IntPtr CFStringCreate(string s)
        => CFStringCreateWithCString(IntPtr.Zero, s, 0x08000100);

    private static IntPtr CFDataCreate(ReadOnlySpan<byte> data)
        => CFDataCreate(IntPtr.Zero, data.ToArray(), data.Length);

    // ---------------- CFDictionary Wrapper ----------------

    private sealed class CFDictionary : IDisposable
    {
        public IntPtr Handle { get; }

        [DllImport(CoreFoundation)]
        private static extern IntPtr CFDictionaryCreate(
            IntPtr allocator,
            IntPtr[] keys,
            IntPtr[] values,
            nint count,
            IntPtr keyCallbacks,
            IntPtr valueCallbacks);

        public CFDictionary(IntPtr[] keys, IntPtr[] values)
        {
            Handle = CFDictionaryCreate(
                IntPtr.Zero,
                keys,
                values,
                keys.Length,
                IntPtr.Zero,
                IntPtr.Zero);

            foreach (var v in values)
                CFRelease(v);
        }

        public void Dispose()
        {
            if (Handle != IntPtr.Zero)
                CFRelease(Handle);
        }
    }

    private static class Sec
    {
        public static readonly IntPtr kSecClass = CFStringCreate("class");
        public static readonly IntPtr kSecClassGenericPassword = CFStringCreate("genp");
        public static readonly IntPtr kSecAttrService = CFStringCreate("svce"); public static readonly IntPtr kSecAttrAccount = CFStringCreate("acct");
        public static readonly IntPtr kSecValueData = CFStringCreate("v_Data");
        public static readonly IntPtr kSecReturnData = CFStringCreate("r_Data");
    }

}
