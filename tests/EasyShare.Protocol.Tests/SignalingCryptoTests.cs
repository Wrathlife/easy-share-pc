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
    public void ConfirmPhraseKnownVectorMatchesAndroid()
    {
        Assert.Equal("CIDER · HERON", SignalingCrypto.ConfirmPhrase("ABCDF23457"));
        Assert.Equal(
            "easyshare/v1/7bd0f4a5a1031562763c51d93c4bdea8",
            SignalingCrypto.MqttCodeTopic("ABCDF23457"));
    }

    [Fact]
    public void TopicHidesRawCode()
    {
        var code = PairingCode.GenerateShort();
        var topic = SignalingCrypto.TopicId(code);
        Assert.Equal(32, topic.Length);
        Assert.DoesNotContain(code, topic, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("easyshare/v1/" + topic, SignalingCrypto.MqttCodeTopic(code));
    }

    [Fact]
    public void TrustTopicsAreDistinctFromCodeTopics()
    {
        var pairId = Guid.NewGuid().ToString();
        var trust = SignalingCrypto.MqttTrustTopic(pairId);
        Assert.StartsWith("easyshare/v1/trust/", trust);
        Assert.DoesNotContain(pairId, trust, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(SignalingCrypto.TopicId(pairId), SignalingCrypto.TrustTopicId(pairId));
    }

    [Fact]
    public void TrustMacExtrasMatchAndroidLayout()
    {
        var extra = SignalingCrypto.TrustOfferMacExtra("pair", "key", "dev", "Name|x");
        Assert.Equal("pair|key|dev|Name/x", extra);
        Assert.Equal("pair|dev|Win", SignalingCrypto.TrustAckMacExtra("pair", "dev", "Win"));
        Assert.Equal("dev|PC", SignalingCrypto.TrustRequestMacExtra("dev", "PC"));
        Assert.Equal("nonce", SignalingCrypto.TrustPongMacExtra("nonce"));
    }

    [Fact]
    public void TrustedDevicesAddRenameRemove()
    {
        var now = 1L;
        var a = new TrustedDevice("p1", "d1", "Phone", "Pixel", "aa", now, now);
        var added = TrustedDevices.Add(Array.Empty<TrustedDevice>(), a, 3);
        var ok = Assert.IsType<TrustedAddResult.Ok>(added);
        Assert.Equal("Phone", TrustedDevices.DisplayName(ok.Devices[0]));
        var renamed = TrustedDevices.Rename(ok.Devices, "p1", "Kitchen tablet");
        Assert.NotNull(renamed);
        Assert.Equal("Kitchen tablet", renamed![0].PeerName);
        Assert.Empty(TrustedDevices.Remove(renamed, "p1"));
    }

    [Fact]
    public void PairingCodeRotationFreezesWhenPeerJoined()
    {
        Assert.False(PairingCodeRotation.ShouldRotate(peerJoined: true, handshakeLocked: false));
        Assert.Equal(0, PairingCodeRotation.RemainingMs(0, PairingCodeRotation.IntervalMs + 10));
        Assert.Equal("ABCDF-23457".Length, PairingCode.FormatTyping("ABCDF23457").Length);
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
        Assert.Null(ProtocolPaths.SanitizeWirePath("C:/Windows/foo"));
        Assert.Null(ProtocolPaths.SanitizeWirePath("C:evil"));
        Assert.Null(ProtocolPaths.SanitizeWirePath("CON"));
        Assert.Null(ProtocolPaths.SanitizeWirePath("foo:bar"));
    }

    [Fact]
    public void BindUnderRootRejectsDriveRelativeNames()
    {
        var root = Path.Combine(Path.GetTempPath(), "ns-recv-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            if (OperatingSystem.IsWindows())
            {
                var combineEscapes = Path.Combine(root, "C:_Windows_foo");
                Assert.False(combineEscapes.StartsWith(root, StringComparison.OrdinalIgnoreCase));
            }
            Assert.Null(ProtocolPaths.BindUnderRoot(root, "C:_Windows_foo"));
            var ok = ProtocolPaths.BindUnderRoot(root, "ok.txt");
            Assert.NotNull(ok);
            Assert.StartsWith(Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar), ok);
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { /* ignore */ }
        }
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
