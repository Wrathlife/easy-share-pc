namespace EasyShare.Protocol;

public sealed record TrustedDevice(
    string PairId,
    string PeerDeviceId,
    string PeerName,
    string PeerDefaultName,
    string TrustKeyHex,
    long CreatedAtEpochMs,
    long LastUsedAtEpochMs);

public sealed record EphemeralPair(
    string PairId,
    string TrustKeyHex,
    string PeerDeviceId,
    string PeerName)
{
    public TrustedDevice AsDevice(string? displayName = null)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var name = string.IsNullOrWhiteSpace(displayName) ? PeerName : displayName!;
        if (string.IsNullOrWhiteSpace(name)) name = "Paired device";
        var advertised = string.IsNullOrWhiteSpace(PeerName) ? name : PeerName;
        return new TrustedDevice(PairId, PeerDeviceId, name, advertised, TrustKeyHex, now, now);
    }
}

public abstract record TrustHandshakeState
{
    public sealed record Idle : TrustHandshakeState;
    public sealed record AwaitingPeer : TrustHandshakeState;
    public sealed record IncomingRequest(string PeerAdvertisedName) : TrustHandshakeState;
    public sealed record Declined : TrustHandshakeState;
    public sealed record TimedOut : TrustHandshakeState;
    public sealed record Complete(
        string PairId,
        string TrustKeyHex,
        string PeerDeviceId,
        string PeerAdvertisedName) : TrustHandshakeState;
}

public abstract record TrustedAddResult
{
    public sealed record Ok(IReadOnlyList<TrustedDevice> Devices) : TrustedAddResult;
    public sealed record AtCap : TrustedAddResult;
    public sealed record Invalid : TrustedAddResult;
}

public static class TrustedDevices
{
    public const int FreeCap = 3;
    public const int PaidCap = 25;
    public const int NameMax = 32;

    public static string? SanitizeName(string raw)
    {
        var trimmed = string.Join(" ", raw.Trim().Replace('\n', ' ').Replace('\r', ' ')
            .Split(' ', StringSplitOptions.RemoveEmptyEntries));
        if (trimmed.Length == 0) return null;
        return trimmed.Length <= NameMax ? trimmed : trimmed[..NameMax];
    }

    public static string AdvertisedName(string model, string fallback = "Windows") =>
        SanitizeName(model) is { Length: > 0 } name ? name : fallback;

    public static string DisplayName(TrustedDevice device) =>
        device.PeerName.Length > 0
            ? device.PeerName
            : device.PeerDefaultName.Length > 0
                ? device.PeerDefaultName
                : "Trusted device";

    public static bool CanAddNew(int currentCount, int max) => currentCount < max;

    public static TrustedAddResult Add(
        IReadOnlyList<TrustedDevice> current,
        TrustedDevice incoming,
        int max)
    {
        if (string.IsNullOrWhiteSpace(incoming.PairId) ||
            string.IsNullOrWhiteSpace(incoming.PeerDeviceId) ||
            string.IsNullOrWhiteSpace(incoming.TrustKeyHex))
        {
            return new TrustedAddResult.Invalid();
        }
        var name = SanitizeName(incoming.PeerName)
            ?? SanitizeName(incoming.PeerDefaultName)
            ?? "Trusted device";
        var device = incoming with
        {
            PeerName = name,
            PeerDefaultName = SanitizeName(incoming.PeerDefaultName) ?? name
        };
        var idx = -1;
        for (var i = 0; i < current.Count; i++)
        {
            if (current[i].PairId == device.PairId || current[i].PeerDeviceId == device.PeerDeviceId)
            {
                idx = i;
                break;
            }
        }
        var list = current.ToList();
        if (idx >= 0)
        {
            var existing = list[idx];
            list[idx] = device with { CreatedAtEpochMs = existing.CreatedAtEpochMs };
            return new TrustedAddResult.Ok(list);
        }
        if (!CanAddNew(list.Count, max)) return new TrustedAddResult.AtCap();
        list.Insert(0, device);
        return new TrustedAddResult.Ok(list);
    }

    public static IReadOnlyList<TrustedDevice>? Rename(
        IReadOnlyList<TrustedDevice> current, string pairId, string rawName)
    {
        var name = SanitizeName(rawName);
        if (name is null) return null;
        var idx = -1;
        for (var i = 0; i < current.Count; i++)
        {
            if (current[i].PairId == pairId) { idx = i; break; }
        }
        if (idx < 0) return null;
        var list = current.ToList();
        list[idx] = list[idx] with { PeerName = name };
        return list;
    }

    public static IReadOnlyList<TrustedDevice> Remove(
        IReadOnlyList<TrustedDevice> current, string pairId) =>
        current.Where(d => d.PairId != pairId).ToList();

    public static IReadOnlyList<TrustedDevice> TouchLastUsed(
        IReadOnlyList<TrustedDevice> current, string pairId, long atEpochMs)
    {
        var idx = -1;
        for (var i = 0; i < current.Count; i++)
        {
            if (current[i].PairId == pairId) { idx = i; break; }
        }
        if (idx < 0) return current;
        var list = current.ToList();
        list[idx] = list[idx] with { LastUsedAtEpochMs = atEpochMs };
        return list;
    }
}

public static class PairingCodeRotation
{
    public const long IntervalMs = 5 * 60 * 1000;

    public static bool ShouldRotate(bool peerJoined, bool handshakeLocked) =>
        !peerJoined && !handshakeLocked;

    public static long RemainingMs(long startedAtEpochMs, long nowEpochMs, long intervalMs = IntervalMs) =>
        Math.Max(0, startedAtEpochMs + intervalMs - nowEpochMs);
}

public static class TrustProbe
{
    public const int TimeoutMs = 8_000;
    public const int RateLimitMs = 2_000;
    public const string FailReason =
        "Couldn’t reach paired device. Check your internet, or pair the devices again.";

    public static bool ShouldPong(IReadOnlyCollection<string> inboxTopics, string mqttTopic) =>
        mqttTopic.Length > 0 && inboxTopics.Contains(mqttTopic);

    public static bool PongMatchesProbe(string expectedProbeNonce, string pongMacExtra) =>
        expectedProbeNonce.Length > 0 && pongMacExtra == expectedProbeNonce;

    public static bool AllowProbeReply(long lastReplyAtMs, long nowMs) =>
        lastReplyAtMs <= 0 || nowMs - lastReplyAtMs >= RateLimitMs;
}

public static class TrustBindPolicy
{
    public const long AwaitingConfirmMs = 180_000;
    public const long UnsavedSessionMs = 600_000;
    public const string AwaitingTimeoutReason =
        "They didn’t confirm in time. Pair the devices again.";
    public const string UnsavedExpiredReason =
        "This pairing wasn’t saved. Pair the devices again.";

    public static bool PersistToStore(bool ephemeralBind, bool persistLocal, bool persistPeer) =>
        !ephemeralBind || (persistLocal && persistPeer);
}
