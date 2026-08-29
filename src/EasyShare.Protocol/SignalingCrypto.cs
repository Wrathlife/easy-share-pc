using System.Security.Cryptography;
using System.Text;

namespace EasyShare.Protocol;

/// <summary>Session crypto for MQTT signaling — parity with Android SignalingCrypto.</summary>
public static class SignalingCrypto
{
    private const int GcmTagBits = 128;
    private const int IvLen = 12;
    private const int Pbkdf2Iterations = 120_000;
    private const int MasterKeyBits = 256;
    private static readonly Encoding Utf8 = Encoding.UTF8;

    private static readonly string[] Words =
    [
        "ABLE", "ACORN", "AMBER", "ANCHOR", "APPLE", "ARROW", "ATLAS", "AZURE",
        "BADGE", "BASIL", "BEACH", "BERRY", "BLAZE", "BLOOM", "BRAVE", "BREEZE",
        "CABLE", "CAMEL", "CANDY", "CEDAR", "CHESS", "CIDER", "CLOUD", "COAST",
        "CORAL", "CRANE", "CREST", "CROWN", "CRYSTAL", "CYCLE", "DELTA", "DOCK",
        "EAGLE", "EMBER", "ENVOY", "FAIRY", "FIELD", "FLAME", "FLINT", "FLORA",
        "FROST", "GALE", "GEMINI", "GLADE", "GLINT", "GRAPE", "GROVE", "HAVEN",
        "HAZEL", "HERON", "HONEY", "IVORY", "JADE", "JOLLY", "KELP", "LARK",
        "LEAF", "LEMON", "LIGHT", "LILAC", "LOTUS", "LUNAR", "MAPLE", "MARBLE",
        "MEADOW", "MINT", "MOSS", "NEBULA", "NORTH", "OCEAN", "OLIVE", "ONYX",
        "ORBIT", "OTTER", "PEACH", "PEARL", "PINE", "PIXEL", "PLUM", "PRAIRIE",
        "QUARTZ", "QUILL", "RIVER", "ROBIN", "SAIL", "SAND", "SILVER", "SKY",
        "SOLAR", "SPARK", "STONE", "STORM", "SUGAR", "SWAN", "THYME", "TIDE",
        "TIGER", "TOPAZ", "TRAIL", "TULIP", "ULTRA", "VALE", "VIVID", "WAVE",
        "WILLOW", "WIND", "WOLF", "ZEBRA", "ZEST", "ZINC", "COMET", "NOVA"
    ];

    public readonly record struct SessionKeys(byte[] Auth, byte[] Enc);

    public static string TopicId(string normalizedCode)
    {
        var digest = SHA256.HashData(Utf8.GetBytes(normalizedCode));
        return Convert.ToHexString(digest).ToLowerInvariant()[..32];
    }

    public static string TrustTopicId(string pairId) => TopicId(pairId);

    public static string MqttCodeTopic(string normalizedCode) => $"easyshare/v1/{TopicId(normalizedCode)}";

    public static string MqttTrustTopic(string pairId) => $"easyshare/v1/trust/{TrustTopicId(pairId)}";

    public static string RandomTrustKeyHex()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public static string ExtraToken(string value) =>
        value.Replace('|', '/').Replace('\n', ' ').Replace('\r', ' ');

    public static string TrustOfferMacExtra(string pairId, string trustKeyHex, string deviceId, string name) =>
        string.Join("|", pairId, trustKeyHex, deviceId, ExtraToken(name));

    public static string TrustAckMacExtra(string pairId, string deviceId, string name) =>
        string.Join("|", pairId, deviceId, ExtraToken(name));

    public static string TrustRequestMacExtra(string deviceId, string name) =>
        string.Join("|", deviceId, ExtraToken(name));

    public static string TrustPongMacExtra(string probeNonce) => probeNonce;

    public static byte[] AuthKey(string normalizedCode) => SessionKeysFrom(normalizedCode).Auth;
    public static byte[] EncKey(string normalizedCode) => SessionKeysFrom(normalizedCode).Enc;

    public static SessionKeys SessionKeysFrom(string normalizedCode)
    {
        var master = MasterKey(normalizedCode);
        return new SessionKeys(
            ExpandKey(master, "easyshare-v1-auth"),
            ExpandKey(master, "easyshare-v1-enc"));
    }

    public static string ConfirmPhrase(string normalizedCode)
    {
        var digest = SHA256.HashData(Utf8.GetBytes("easyshare-v1-confirm|" + normalizedCode));
        var a = Words[digest[0] % Words.Length];
        var b = Words[digest[1] % Words.Length];
        return $"{a} · {b}";
    }

    private static byte[] MasterKey(string normalizedCode)
    {
        var salt = SHA256.HashData(Utf8.GetBytes("easyshare-v1-salt|" + normalizedCode));
        // Android Conscrypt / BouncyCastle PBKDF2WithHmacSHA256 encodes the password as UTF-8
        // (not UTF-16BE). Using UTF-16BE made Windows envelopes undecryptable on the phone.
        return Rfc2898DeriveBytes.Pbkdf2(
            Utf8.GetBytes(normalizedCode),
            salt,
            Pbkdf2Iterations,
            HashAlgorithmName.SHA256,
            MasterKeyBits / 8);
    }

    private static byte[] ExpandKey(byte[] master, string label)
    {
        using var hmac = new HMACSHA256(master);
        return hmac.ComputeHash(Utf8.GetBytes(label));
    }

    public static string MacHex(byte[] key, string canonical)
    {
        using var hmac = new HMACSHA256(key);
        return Convert.ToHexString(hmac.ComputeHash(Utf8.GetBytes(canonical))).ToLowerInvariant();
    }

    public static bool VerifyMac(byte[] key, string canonical, string macHex)
    {
        if (string.IsNullOrWhiteSpace(macHex) || macHex.Length != 64) return false;
        var expected = MacHex(key, canonical);
        var a = Utf8.GetBytes(expected);
        var b = Utf8.GetBytes(macHex.ToLowerInvariant());
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    public static string RandomNonce()
    {
        var bytes = new byte[12];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static string Canonical(
        string role, string eventName, long ts, long exp, string nonce, string extra = "") =>
        string.Join("|", role, eventName, ts.ToString(), exp.ToString(), nonce, extra);

    public static string SealEnvelope(byte[] encKey, string innerJson)
    {
        var iv = new byte[IvLen];
        RandomNumberGenerator.Fill(iv);
        var plain = Utf8.GetBytes(innerJson);
        var cipher = new byte[plain.Length];
        var tag = new byte[GcmTagBits / 8];
        using (var gcm = new AesGcm(encKey, GcmTagBits / 8))
        {
            gcm.Encrypt(iv, plain, cipher, tag);
        }
        var packed = new byte[iv.Length + cipher.Length + tag.Length];
        Buffer.BlockCopy(iv, 0, packed, 0, iv.Length);
        Buffer.BlockCopy(cipher, 0, packed, iv.Length, cipher.Length);
        Buffer.BlockCopy(tag, 0, packed, iv.Length + cipher.Length, tag.Length);
        var blob = Convert.ToBase64String(packed);
        return EnvelopeJson.Encode(1, blob);
    }

    public static string? OpenEnvelope(byte[] encKey, string outerPayload)
    {
        var parsed = EnvelopeJson.Decode(outerPayload);
        if (parsed is null || parsed.Value.Version != 1 || string.IsNullOrWhiteSpace(parsed.Value.Blob))
            return null;
        byte[] packed;
        try { packed = Convert.FromBase64String(parsed.Value.Blob); }
        catch { return null; }
        if (packed.Length <= IvLen + 16) return null;
        var iv = packed.AsSpan(0, IvLen);
        var tagLen = GcmTagBits / 8;
        var ctLen = packed.Length - IvLen - tagLen;
        if (ctLen < 0) return null;
        var cipher = packed.AsSpan(IvLen, ctLen);
        var tag = packed.AsSpan(IvLen + ctLen, tagLen);
        var plain = new byte[ctLen];
        try
        {
            using var gcm = new AesGcm(encKey, tagLen);
            gcm.Decrypt(iv, cipher, tag, plain);
            return Utf8.GetString(plain);
        }
        catch
        {
            return null;
        }
    }
}

/// <summary>Minimal JSON envelope codec for {"v":N,"blob":"..."}.</summary>
public static class EnvelopeJson
{
    public readonly record struct Envelope(int Version, string Blob);

    public static string Encode(int version, string blob)
    {
        if (blob.Any(c => !(char.IsLetterOrDigit(c) || c is '+' or '/' or '=')))
            throw new ArgumentException("blob must be standard Base64");
        return $"{{\"v\":{version},\"blob\":\"{blob}\"}}";
    }

    public static Envelope? Decode(string raw)
    {
        var trimmed = raw.Trim();
        if (!trimmed.StartsWith('{') || !trimmed.EndsWith('}')) return null;
        var body = trimmed[1..^1];
        int? version = null;
        string? blob = null;
        var i = 0;
        while (i < body.Length)
        {
            i = SkipWs(body, i);
            if (i >= body.Length) break;
            if (body[i] != '"') return null;
            var keyEnd = body.IndexOf('"', i + 1);
            if (keyEnd < 0) return null;
            var key = body[(i + 1)..keyEnd];
            i = SkipWs(body, keyEnd + 1);
            if (i >= body.Length || body[i] != ':') return null;
            i = SkipWs(body, i + 1);
            switch (key)
            {
                case "v":
                {
                    var start = i;
                    while (i < body.Length && (char.IsDigit(body[i]) || body[i] == '-')) i++;
                    if (!int.TryParse(body[start..i], out var v)) return null;
                    version = v;
                    break;
                }
                case "blob":
                {
                    if (i >= body.Length || body[i] != '"') return null;
                    var start = i + 1;
                    var end = body.IndexOf('"', start);
                    if (end < 0) return null;
                    blob = body[start..end];
                    i = end + 1;
                    break;
                }
                default:
                {
                    if (i < body.Length && body[i] == '"')
                    {
                        var end = body.IndexOf('"', i + 1);
                        if (end < 0) return null;
                        i = end + 1;
                    }
                    else
                    {
                        while (i < body.Length && body[i] is not (',' or '}')) i++;
                    }
                    break;
                }
            }
            i = SkipWs(body, i);
            if (i < body.Length && body[i] == ',') i++;
        }
        if (version is null || blob is null) return null;
        return new Envelope(version.Value, blob);
    }

    private static int SkipWs(string s, int start)
    {
        var i = start;
        while (i < s.Length && char.IsWhiteSpace(s[i])) i++;
        return i;
    }
}
