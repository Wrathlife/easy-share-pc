using System.Security.Cryptography;
using System.Text;

namespace EasyShare.Protocol;

public static class ProtocolPaths
{
    public const int MaxManifestFiles = 200;
    public const long MaxFileBytes = 100L * 1024L * 1024L * 1024L;

    public static string? SanitizeWirePath(string raw)
    {
        var trimmed = raw.Trim().Replace('\\', '/');
        if (trimmed.Length == 0 || trimmed.Length > 180) return null;
        if (trimmed.StartsWith('/') || trimmed.Contains("://", StringComparison.Ordinal)) return null;
        var parts = trimmed.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return null;
        if (parts.Any(p => p is "." or "..")) return null;
        return string.Join('/', parts);
    }

    public static string ShortHash(string value)
    {
        if (value.Length == 0) return "";
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(digest).ToLowerInvariant()[..16];
    }

    public static string Sha256Hex(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
