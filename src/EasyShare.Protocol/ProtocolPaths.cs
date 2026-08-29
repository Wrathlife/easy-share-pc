using System.Security.Cryptography;
using System.Text;

namespace EasyShare.Protocol;

public static class ProtocolPaths
{
    public const int MaxManifestFiles = 200;
    public const long MaxFileBytes = 100L * 1024L * 1024L * 1024L;

    private static readonly HashSet<string> ReservedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    public static string? SanitizeWirePath(string raw)
    {
        var trimmed = raw.Trim().Replace('\\', '/');
        if (trimmed.Length == 0 || trimmed.Length > 180) return null;
        if (trimmed.StartsWith('/') || trimmed.Contains("://", StringComparison.Ordinal)) return null;
        var parts = trimmed.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return null;
        foreach (var p in parts)
        {
            if (p is "." or "..") return null;
            if (p.Contains(':') || p.IndexOfAny(['<', '>', '"', '|', '?', '*']) >= 0) return null;
            if (IsReservedName(p)) return null;
        }
        return string.Join('/', parts);
    }

    /// <summary>
    /// Flatten a sanitized wire path and resolve it under <paramref name="root"/>.
    /// Returns null if the result would leave the root (drive-letter / combine tricks).
    /// </summary>
    public static string? BindUnderRoot(string root, string sanitizedWirePath)
    {
        if (string.IsNullOrWhiteSpace(root) || string.IsNullOrWhiteSpace(sanitizedWirePath)) return null;
        var safe = sanitizedWirePath.Replace('/', '_');
        if (safe.Length > 160) safe = safe[..160];
        if (safe.Contains(':') || Path.IsPathRooted(safe)) return null;
        string combined;
        string fullRoot;
        string fullFile;
        try
        {
            combined = Path.Combine(root, safe);
            fullRoot = Path.GetFullPath(root);
            fullFile = Path.GetFullPath(combined);
        }
        catch
        {
            return null;
        }
        var rootPrefix = fullRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                         + Path.DirectorySeparatorChar;
        if (!fullFile.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(fullFile, fullRoot, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
        return fullFile;
    }

    public static string ShortHash(string value)
    {
        if (value.Length == 0) return "";
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(digest).ToLowerInvariant()[..16];
    }

    public static string Sha256Hex(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static bool IsReservedName(string part)
    {
        var name = part;
        var dot = name.IndexOf('.');
        if (dot >= 0) name = name[..dot];
        return ReservedNames.Contains(name);
    }
}
