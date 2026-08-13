using EasyShare.Protocol;
using Xunit;

namespace EasyShare.Protocol.Tests;

public class SignalingCryptoTests
{
    [Fact]
    public void MacRoundTrip()
    {
        var code = PairingCode.GenerateShort();
        var key = SignalingCrypto.AuthKey(code);
        var canonical = SignalingCrypto.Canonical("h", "ready", 1_700_000_000L, 1_700_000_600L, "nonce1");
        var mac = SignalingCrypto.MacHex(key, canonical);
        Assert.True(SignalingCrypto.VerifyMac(key, canonical, mac));
        Assert.False(SignalingCrypto.VerifyMac(key, canonical + "x", mac));
    }

    [Fact]
    public void SessionKeysDerivesBothFromOnePass()
    {
        var code = PairingCode.GenerateShort();
        var keys = SignalingCrypto.SessionKeysFrom(code);
        Assert.Equal(32, keys.Auth.Length);
        Assert.Equal(32, keys.Enc.Length);
        Assert.False(keys.Auth.SequenceEqual(keys.Enc));
        Assert.True(keys.Auth.SequenceEqual(SignalingCrypto.AuthKey(code)));
        Assert.True(keys.Enc.SequenceEqual(SignalingCrypto.EncKey(code)));
    }

    [Fact]
    public void EnvelopeRoundTripHidesPlaintext()
    {
        var code = PairingCode.GenerateShort();
        var key = SignalingCrypto.EncKey(code);
        var inner = """{"r":"h","e":"manifest","files":[{"n":"secret/path.txt","s":12}]}""";
        var outer = SignalingCrypto.SealEnvelope(key, inner);
        Assert.DoesNotContain("secret/path.txt", outer);
        Assert.Equal(inner, SignalingCrypto.OpenEnvelope(key, outer));
        Assert.Null(SignalingCrypto.OpenEnvelope(SignalingCrypto.EncKey("OTHERCODE12"), outer));
    }

    [Fact]
    public void EnvelopeJsonAllowsWhitespaceAndKeyOrder()
    {
        var packed = EnvelopeJson.Encode(1, "YWJj");
        Assert.Equal("""{"v":1,"blob":"YWJj"}""", packed);
        var spaced = """{ "blob" : "YWJj" , "v" : 1 }""";
        var decoded = EnvelopeJson.Decode(spaced);
        Assert.NotNull(decoded);
        Assert.Equal(1, decoded!.Value.Version);
        Assert.Equal("YWJj", decoded.Value.Blob);
    }

    [Fact]
    public void ConfirmPhraseStablePerCode()
    {
        var code = PairingCode.GenerateShort();
        var a = SignalingCrypto.ConfirmPhrase(code);
        Assert.Equal(a, SignalingCrypto.ConfirmPhrase(code));
        Assert.Contains("·", a);
    }

    [Fact]
    public void TopicHidesRawCode()
    {
        var code = PairingCode.GenerateShort();
        var topic = SignalingCrypto.TopicId(code);
        Assert.Equal(32, topic.Length);
        Assert.DoesNotContain(code, topic, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PairingCodeValidation()
    {
        var good = PairingCode.GenerateShort();
        Assert.Equal(PairingCode.TotalLength, good.Length);
        Assert.True(PairingCode.IsValidShort(good));
        Assert.Equal(
            good[..PairingCode.LetterCount] + "-" + good[^PairingCode.DigitCount..],
            PairingCode.FormatForDisplay(good));
        Assert.False(PairingCode.IsValidShort("ABCDF23457XXXX"));
        Assert.False(PairingCode.IsValidShort("ABC12"));
    }

    [Fact]
    public void SanitizeWirePath()
    {
        Assert.Equal("a/b.txt", ProtocolPaths.SanitizeWirePath("a/b.txt"));
        Assert.Null(ProtocolPaths.SanitizeWirePath("../etc/passwd"));
        Assert.Null(ProtocolPaths.SanitizeWirePath("/abs"));
        Assert.Null(ProtocolPaths.SanitizeWirePath("a/./b"));
    }

    [Fact]
    public void DcFrameRoundTrip()
    {
        var begin = DcFrames.EncodeFileBegin(0, "photos/a.jpg", 12345);
        Assert.True(DcFrames.TryParse(begin, out var type, out var payload));
        Assert.Equal(DcFrames.TypeFileBegin, type);
        Assert.True(payload.Length > 0);
        var hello = DcFrames.EncodeHello();
        Assert.Equal(DcFrames.TypeHello, hello[0]);
    }

    [Fact]
    public void ShortHashLength()
    {
        Assert.Equal(16, ProtocolPaths.ShortHash("candidate-line").Length);
        Assert.Equal("", ProtocolPaths.ShortHash(""));
    }
}
