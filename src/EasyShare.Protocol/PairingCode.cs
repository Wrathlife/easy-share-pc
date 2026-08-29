using System.Security.Cryptography;
using System.Text;

namespace EasyShare.Protocol;

/// <summary>Human-facing pairing codes — parity with Android PairingCode.</summary>
public static class PairingCode
{
    private static readonly char[] Letters = "ABCDEFGHJKLMNPQRSTUVWXYZ".ToCharArray();
    private static readonly char[] Digits = "23456789".ToCharArray();

    public const int LetterCount = 5;
    public const int DigitCount = 5;
    public const int TotalLength = LetterCount + DigitCount;

    public static string GenerateShort(int letterCount = LetterCount, int digitCount = DigitCount)
    {
        Span<char> letterPart = stackalloc char[letterCount];
        Span<char> digitPart = stackalloc char[digitCount];
        for (var i = 0; i < letterCount; i++)
            letterPart[i] = Letters[RandomNumberGenerator.GetInt32(Letters.Length)];
        for (var i = 0; i < digitCount; i++)
            digitPart[i] = Digits[RandomNumberGenerator.GetInt32(Digits.Length)];
        return new string(letterPart) + new string(digitPart);
    }

    public static string FormatForDisplay(string raw)
    {
        var code = Normalize(raw);
        if (code.Length != TotalLength) return code;
        return code[..LetterCount] + "-" + code[^DigitCount..];
    }

    /// <summary>Hyphen after the letter block while typing (wire form has no hyphen).</summary>
    public static string FormatTyping(string raw)
    {
        var code = SanitizeTyping(raw);
        if (code.Length <= LetterCount) return code;
        return code[..LetterCount] + "-" + code[LetterCount..];
    }

    public static string Normalize(string raw) =>
        string.Concat(raw.Trim().ToUpperInvariant().Replace("-", "").Replace(" ", "")
            .Where(char.IsLetterOrDigit));

    public static string SanitizeTyping(string raw) => Normalize(raw).Length > TotalLength
        ? Normalize(raw)[..TotalLength]
        : Normalize(raw);

    public static bool IsValidShort(string raw)
    {
        var code = Normalize(raw);
        if (code.Length != TotalLength) return false;
        var letterPart = code[..LetterCount];
        var digitPart = code[^DigitCount..];
        if (letterPart.Any(c => Array.IndexOf(Letters, c) < 0)) return false;
        if (digitPart.Any(c => Array.IndexOf(Digits, c) < 0)) return false;
        return true;
    }
}
