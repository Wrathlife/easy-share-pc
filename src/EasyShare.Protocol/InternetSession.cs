using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using MQTTnet;
using MQTTnet.Client;
using MQTTnet.Protocol;

namespace EasyShare.Protocol;

/// <summary>
/// Internet pairing + encrypted MQTT signaling.
/// File bytes: WebRTC DataChannel by default; MQTT AES when encrypt is on or WebRTC fails (~28s).
/// </summary>
public sealed class InternetSession : IAsyncDisposable
{
    public const string BrokerHost = "broker.emqx.io";
    public const int BrokerPort = 8883;
    public const long SessionTtlSec = 10 * 60;
    public const long InboxTtlSec = 60 * 60;
    public const int WebrtcBudgetMs = 28_000;
    public const string TransferCancelled = "Transfer cancelled";
    public const string TransferCancelledByPeer = "Transfer cancelled by the other device";

    private enum ByteTransferMode { Undecided, WebRtc, Mqtt }

    private sealed record InboxEntry(TrustedDevice Device, SignalingCrypto.SessionKeys Keys);
    private sealed record PendingTrustOffer(string PairId, string TrustKeyHex, string PeerDeviceId, string PeerName);

    private readonly object _gate = new();
    private readonly SemaphoreSlim _signalLock = new(1, 1);
    private IMqttClient? _client;
    private string? _topic;
    private string? _role;
    private string? _normalizedCode;
    private string? _sessionTopicId;
    private byte[] _authKey = Array.Empty<byte>();
    private byte[] _encKey = Array.Empty<byte>();
    private long _sessionExpEpochSec;
    private bool _guestLocked;
    private bool _manifestFrozen;
    private bool _localConfirmed;
    private bool _peerConfirmed;
    private bool _skipPhraseConfirm;
    private bool _forceMqttRelay;
    private ByteTransferMode _byteMode = ByteTransferMode.Undecided;
    private bool _encryptFileTransfer;
    private List<SharedFileInfo> _localManifest = new();
    private readonly ReplayNonceCache _seenNonces = new();
    private string? _pendingRemoteOffer;
    private string? _pendingRemoteAnswer;
    private readonly List<IceCandidateDto> _pendingRemoteIce = new();
    private WebRtcPeer? _webrtc;
    private DataChannelTransfer? _dcTransfer;
    private MqttFileTransfer? _mqttTransfer;
    private CancellationTokenSource? _sessionCts;
    private CancellationTokenSource? _joinRetryCts;
    private CancellationTokenSource? _readyRetryCts;
    private CancellationTokenSource? _probeCts;
    private int _sessionGen;
    private bool _transferComplete;
    private string? _transferFailed;
    private Task? _transferTask;
    private IReadOnlyList<LocalShareEntry> _hostEntries = Array.Empty<LocalShareEntry>();
    private string? _guestReceiveRoot;

    private readonly Dictionary<string, InboxEntry> _inboxByTopic = new(StringComparer.Ordinal);
    private bool _inboxLocked;
    private bool _trustProbePending;
    private string? _trustProbeNonce;
    private readonly Dictionary<string, long> _lastProbePongAtMs = new(StringComparer.Ordinal);
    private PendingTrustOffer? _pendingTrustOffer;
    private bool _localWantsTrust;
    private bool _peerWantsTrust;
    private bool _ephemeralBind;
    private bool _persistLocal;
    private bool _persistPeer;
    private bool _hostSentTrustOffer;
    private string? _localDeviceId;
    private string? _localAdvertisedName;
    private string? _hostPairId;
    private string? _hostTrustKeyHex;
    private string? _pendingPeerAdvertisedName;
    private EphemeralPair? _ephemeralPair;
    private TrustHandshakeState _trustHandshake = new TrustHandshakeState.Idle();

    public event Action<PairingState>? StateChanged;
    public event Action<IReadOnlyList<SharedFileInfo>>? RemoteFilesChanged;
    public event Action<TransferProgress?>? ProgressChanged;
    public event Action<IReadOnlyList<SavedFileRecord>>? SavedFilesChanged;
    public event Action? TransferCompleted;
    public event Action<string>? TransferFailed;
    public event Action<TrustHandshakeState>? TrustHandshakeChanged;
    public event Action<EphemeralPair?>? EphemeralPairChanged;

    public PairingState State { get; private set; } = new PairingState.Idle();
    public IReadOnlyList<SharedFileInfo> RemoteFiles { get; private set; } = Array.Empty<SharedFileInfo>();
    public IReadOnlyList<SavedFileRecord> SavedFiles { get; private set; } = Array.Empty<SavedFileRecord>();
    public bool IsTransferComplete => _transferComplete;
    public string? TransferFailReason => _transferFailed;
    public string? SessionId => _sessionTopicId;
    public EphemeralPair? EphemeralPair => _ephemeralPair;
    public TrustHandshakeState TrustHandshake => _trustHandshake;
    public bool IsTransferOrchestratorActive => _transferTask is { IsCompleted: false };
    public bool IsPeerJoined =>
        _guestLocked || State is PairingState.Confirming or PairingState.Paired;

    public async Task StartHostAsync(string code, IReadOnlyList<SharedFileInfo> files, CancellationToken ct = default)
    {
        _localManifest = files.Take(ProtocolPaths.MaxManifestFiles).ToList();
        var normalized = PairingCode.Normalize(code);
        await StartSessionAsync(
            normalized,
            SignalingCrypto.MqttCodeTopic(normalized),
            SignalingCrypto.TopicId(normalized),
            "host",
            skipPhraseConfirm: false,
            probeFirst: false,
            ct).ConfigureAwait(false);
    }

    public Task StartHostPairingAsync(string code, CancellationToken ct = default) =>
        StartHostAsync(code, Array.Empty<SharedFileInfo>(), ct);

    public async Task StartGuestAsync(string code, CancellationToken ct = default)
    {
        _localManifest = new List<SharedFileInfo>();
        SetRemoteFiles(Array.Empty<SharedFileInfo>());
        var normalized = PairingCode.Normalize(code);
        await StartSessionAsync(
            normalized,
            SignalingCrypto.MqttCodeTopic(normalized),
            SignalingCrypto.TopicId(normalized),
            "guest",
            skipPhraseConfirm: false,
            probeFirst: false,
            ct).ConfigureAwait(false);
    }

    public async Task StartHostTrustedAsync(
        TrustedDevice device,
        IReadOnlyList<SharedFileInfo> files,
        CancellationToken ct = default)
    {
        _localManifest = files.Take(ProtocolPaths.MaxManifestFiles).ToList();
        await StartSessionAsync(
            device.TrustKeyHex,
            SignalingCrypto.MqttTrustTopic(device.PairId),
            SignalingCrypto.TrustTopicId(device.PairId),
            "host",
            skipPhraseConfirm: true,
            probeFirst: true,
            ct).ConfigureAwait(false);
    }

    public async Task StartGuestTrustInboxAsync(IReadOnlyList<TrustedDevice> devices, CancellationToken ct = default)
    {
        if (devices.Count == 0) return;
        await StopAsync().ConfigureAwait(false);
        _role = "guest";
        _skipPhraseConfirm = true;
        _inboxLocked = false;
        _inboxByTopic.Clear();
        // One PBKDF2 (120k iterations) per saved device — never on the UI thread.
        var inboxEntries = await Task.Run(() => devices
            .Select(device => (
                Topic: SignalingCrypto.MqttTrustTopic(device.PairId),
                Entry: new InboxEntry(device, SignalingCrypto.SessionKeysFrom(device.TrustKeyHex))))
            .ToList(), ct).ConfigureAwait(false);
        foreach (var (topic, entry) in inboxEntries)
            _inboxByTopic[topic] = entry;
        _sessionExpEpochSec = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + InboxTtlSec;
        SetState(new PairingState.ListeningForTrusted());
        await ConnectMqttAsync("g", secret: null, ct).ConfigureAwait(false);
    }

    public void AcceptTrustedIncoming()
    {
        if (State is not PairingState.TrustedIncoming) return;
        if (_inboxLocked) return;
        _inboxLocked = true;
        _skipPhraseConfirm = true;
        SetState(new PairingState.Waiting());
        _ = PublishSignedAsync("g", "join");
        StartJoinRetry();
    }

    public void DeclineTrustedIncoming()
    {
        if (State is not PairingState.TrustedIncoming) return;
        _topic = null;
        _authKey = Array.Empty<byte>();
        _encKey = Array.Empty<byte>();
        _sessionTopicId = null;
        _inboxLocked = false;
        SetRemoteFiles(Array.Empty<SharedFileInfo>());
        SetState(new PairingState.ListeningForTrusted());
    }

    public void StartEphemeralBind(string localDeviceId, string advertisedName)
    {
        if (State is not PairingState.Paired) return;
        if (_ephemeralPair is not null) return;
        _ephemeralBind = true;
        _persistLocal = false;
        _persistPeer = false;
        _localDeviceId = localDeviceId;
        _localAdvertisedName = advertisedName;
        _localWantsTrust = true;
        if (_role == "host")
        {
            _peerWantsTrust = true;
            _hostSentTrustOffer = false;
            _ = SendTrustOfferIfNeededAsync();
            _ = RetryTrustOfferAsync();
        }
        else if (_pendingTrustOffer is not null)
        {
            _ = AckAndCompleteAsync(_pendingTrustOffer);
        }
    }

    public void RequestTrustBind(string localDeviceId, string advertisedName)
    {
        if (State is not PairingState.Paired and not PairingState.Confirming) return;
        if (_trustHandshake is TrustHandshakeState.Complete or TrustHandshakeState.TimedOut) return;
        _localDeviceId = localDeviceId;
        _localAdvertisedName = advertisedName;
        _localWantsTrust = true;
        _persistLocal = true;
        _ = PublishTrustRequestAsync();
        if (_persistPeer)
            CompletePersistFromEphemeralOrOffer();
        else
            SetTrustHandshake(new TrustHandshakeState.AwaitingPeer());
    }

    public void DeclineTrustBind()
    {
        if (_trustHandshake is TrustHandshakeState.Complete) return;
        _persistLocal = false;
        _persistPeer = false;
        if (!_ephemeralBind)
        {
            _localWantsTrust = false;
            _peerWantsTrust = false;
            _hostSentTrustOffer = false;
        }
        var roleChar = _role == "host" ? "h" : "g";
        _ = PublishSignedAsync(roleChar, "trust-decline");
        SetTrustHandshake(new TrustHandshakeState.Idle());
    }

    public void ConfirmLocalPairing()
    {
        lock (_gate)
        {
            if (State is not PairingState.Confirming) return;
            if (_localConfirmed) return;
            _localConfirmed = true;
        }
        var roleChar = _role == "host" ? "h" : "g";
        _ = PublishSignedAsync(roleChar, "confirm");
        RefreshConfirming();
        MaybeCompletePair();
    }

    public void RejectLocalPairing()
    {
        _ = StopAsync();
        SetState(new PairingState.Failed("Pairing cancelled — devices did not match"));
    }

    public void CancelTransfer()
    {
        if (_transferComplete) return;
        var roleChar = _role == "host" ? "h" : "g";
        AbortActiveTransfer(TransferCancelled);
        _ = PublishSignedAsync(roleChar, "xfer-cancel");
    }

    public async Task StartHostFileTransferAsync(
        IReadOnlyList<LocalShareEntry> entries,
        bool encryptFileTransfer,
        CancellationToken ct = default)
    {
        if (IsTransferOrchestratorActive) return;
        _encryptFileTransfer = encryptFileTransfer;
        _hostEntries = entries;
        _transferComplete = false;
        _transferFailed = null;
        _transferTask = RunHostTransferAsync(entries, encryptFileTransfer, ct);
        await _transferTask.ConfigureAwait(false);
    }

    public async Task PrepareGuestFileSinkAsync(
        string receiveRoot,
        IReadOnlyList<SharedFileInfo> expected,
        bool encryptFileTransfer,
        bool beginTransfer,
        CancellationToken ct = default)
    {
        _encryptFileTransfer = encryptFileTransfer;
        var sessionId = _sessionTopicId ?? (_normalizedCode is null ? "session" : SignalingCrypto.TopicId(_normalizedCode));
        var sink = Path.Combine(receiveRoot, sessionId);
        _guestReceiveRoot = sink;
        EnsureMqttFileTransfer();
        _mqttTransfer!.PrepareGuestSink(sink, expected);
        if (!beginTransfer) return;
        if (IsTransferOrchestratorActive) return;
        _transferTask = RunGuestTransferAsync(expected, receiveRoot, encryptFileTransfer, ct);
        await _transferTask.ConfigureAwait(false);
    }

    public async Task StopAsync()
    {
        Interlocked.Increment(ref _sessionGen);
        _joinRetryCts?.Cancel();
        _readyRetryCts?.Cancel();
        _probeCts?.Cancel();
        _sessionCts?.Cancel();
        CloseWebRtc();
        _mqttTransfer?.Reset();
        _mqttTransfer = null;
        _transferTask = null;
        if (_client is not null)
        {
            try { if (_client.IsConnected) await _client.DisconnectAsync().ConfigureAwait(false); } catch { /* ignore */ }
            _client.Dispose();
            _client = null;
        }
        _topic = null;
        _role = null;
        _normalizedCode = null;
        _sessionTopicId = null;
        _authKey = Array.Empty<byte>();
        _encKey = Array.Empty<byte>();
        _guestLocked = false;
        _manifestFrozen = false;
        _localConfirmed = false;
        _peerConfirmed = false;
        _skipPhraseConfirm = false;
        _forceMqttRelay = false;
        _byteMode = ByteTransferMode.Undecided;
        _pendingRemoteOffer = null;
        _pendingRemoteAnswer = null;
        lock (_pendingRemoteIce) _pendingRemoteIce.Clear();
        _inboxByTopic.Clear();
        _inboxLocked = false;
        _trustProbePending = false;
        _trustProbeNonce = null;
        _lastProbePongAtMs.Clear();
        _pendingTrustOffer = null;
        _localWantsTrust = false;
        _peerWantsTrust = false;
        _ephemeralBind = false;
        _persistLocal = false;
        _persistPeer = false;
        _hostSentTrustOffer = false;
        _localDeviceId = null;
        _localAdvertisedName = null;
        _hostPairId = null;
        _hostTrustKeyHex = null;
        _pendingPeerAdvertisedName = null;
        _ephemeralPair = null;
        _trustHandshake = new TrustHandshakeState.Idle();
        _transferComplete = false;
        _transferFailed = null;
        _seenNonces.Clear();
        EphemeralPairChanged?.Invoke(null);
        TrustHandshakeChanged?.Invoke(_trustHandshake);
        SetState(new PairingState.Idle());
    }

    public ValueTask DisposeAsync() => new(StopAsync());

    private async Task StartSessionAsync(
        string secret,
        string mqttTopic,
        string sessionId,
        string role,
        bool skipPhraseConfirm,
        bool probeFirst,
        CancellationToken ct)
    {
        await StopAsync().ConfigureAwait(false);
        if (role != "guest" && string.IsNullOrWhiteSpace(secret))
        {
            SetState(new PairingState.Failed("Invalid share code format"));
            return;
        }
        if (mqttTopic.StartsWith("easyshare/v1/trust/", StringComparison.Ordinal))
        {
            // Trusted sessions use the trust key as PBKDF2 secret (may not look like a share code).
        }
        else if (!PairingCode.IsValidShort(secret))
        {
            SetState(new PairingState.Failed("Invalid share code format"));
            return;
        }

        _role = role;
        _normalizedCode = secret;
        _skipPhraseConfirm = skipPhraseConfirm;
        _sessionTopicId = sessionId;
        _topic = mqttTopic;
        _sessionExpEpochSec = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + SessionTtlSec;
        _trustProbePending = probeFirst;
        SetState(new PairingState.Connecting());
        await ConnectMqttAsync(role[..1], secret, ct).ConfigureAwait(false);
    }

    private async Task ConnectMqttAsync(string rolePrefix, string? secret, CancellationToken ct)
    {
        var gen = Interlocked.Increment(ref _sessionGen);
        _sessionCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        if (secret is not null)
        {
            // PBKDF2 (120k iterations) is deliberately slow — keep it off the caller's
            // thread. Session starts run on the WPF dispatcher and this was freezing
            // the window on every pairing-hub entry, making the UI visibly re-layout.
            var keys = await Task.Run(() => SignalingCrypto.SessionKeysFrom(secret), ct).ConfigureAwait(false);
            if (gen != _sessionGen) return;
            _authKey = keys.Auth;
            _encKey = keys.Enc;
        }

        var factory = new MqttFactory();
        var client = factory.CreateMqttClient();
        _client = client;
        client.ApplicationMessageReceivedAsync += e =>
        {
            var payload = Encoding.UTF8.GetString(e.ApplicationMessage.PayloadSegment);
            var topic = e.ApplicationMessage.Topic;
            _ = Task.Run(() => OnMessageAsync(topic, payload));
            return Task.CompletedTask;
        };
        client.ConnectedAsync += async _ =>
        {
            if (gen != _sessionGen) return;
            await OnConnectedAsync(gen).ConfigureAwait(false);
        };

        var options = new MqttClientOptionsBuilder()
            .WithTcpServer(BrokerHost, BrokerPort)
            .WithClientId($"es-{rolePrefix}-{Guid.NewGuid():N}")
            .WithTlsOptions(o =>
            {
                o.UseTls();
                o.WithCertificateValidationHandler(BrokerTls.IsTrusted);
            })
            .WithCleanSession()
            .WithKeepAlivePeriod(TimeSpan.FromSeconds(20))
            .WithTimeout(TimeSpan.FromSeconds(20))
            .WithProtocolVersion(MQTTnet.Formatter.MqttProtocolVersion.V311)
            .Build();

        Exception? last = null;
        for (var attempt = 1; attempt <= 4; attempt++)
        {
            if (gen != _sessionGen) return;
            try
            {
                await client.ConnectAsync(options, _sessionCts.Token).ConfigureAwait(false);

                return;
            }
            catch (Exception ex)
            {
                last = ex;
                if (attempt < 4)
                {
                    try
                    {
                        await Task.Delay(400 * attempt, _sessionCts.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }
                }
            }
        }

        if (gen != _sessionGen || last is null) return;
        SetState(new PairingState.Failed(last.Message));
    }

    private async Task OnConnectedAsync(int gen)
    {
        if (gen != _sessionGen || _client is null) return;
        if (_inboxByTopic.Count > 0 && !_inboxLocked)
        {
            foreach (var topic in _inboxByTopic.Keys)
                await _client.SubscribeAsync(topic, MqttQualityOfServiceLevel.AtLeastOnce).ConfigureAwait(false);
            if (State is PairingState.Idle)
                SetState(new PairingState.ListeningForTrusted());
            return;
        }

        if (_topic is null || _role is null) return;
        await _client.SubscribeAsync(_topic, MqttQualityOfServiceLevel.AtLeastOnce).ConfigureAwait(false);
        if (_role == "host")
        {
            if (_trustProbePending)
            {
                await PublishTrustProbeAsync().ConfigureAwait(false);
                ScheduleProbeTimeout(gen);
            }
            else
            {
                await PublishSignedAsync("h", "ready").ConfigureAwait(false);
                await PublishManifestAsync().ConfigureAwait(false);
                if (State is not PairingState.Paired and not PairingState.Confirming)
                    SetState(new PairingState.Waiting());
                StartReadyRetry();
            }
        }
        else
        {
            if (State is PairingState.ListeningForTrusted or PairingState.TrustedIncoming)
                return;
            await PublishSignedAsync("g", "join").ConfigureAwait(false);
            if (State is not PairingState.Paired and not PairingState.Confirming)
                SetState(new PairingState.Waiting());
            StartJoinRetry();
        }
    }

    private void StartJoinRetry()
    {
        _joinRetryCts?.Cancel();
        _joinRetryCts = new CancellationTokenSource();
        var token = _joinRetryCts.Token;
        _ = Task.Run(async () =>
        {
            while (!token.IsCancellationRequested &&
                   State is not PairingState.Paired and not PairingState.Confirming and not PairingState.Failed)
            {
                try { await Task.Delay(2000, token).ConfigureAwait(false); }
                catch { return; }
                if (State is PairingState.Paired or PairingState.Confirming or PairingState.Failed) return;
                await PublishSignedAsync("g", "join").ConfigureAwait(false);
            }
        }, token);
    }

    private void StartReadyRetry()
    {
        _readyRetryCts?.Cancel();
        _readyRetryCts = new CancellationTokenSource();
        var token = _readyRetryCts.Token;
        _ = Task.Run(async () =>
        {
            while (!token.IsCancellationRequested &&
                   State is PairingState.Waiting &&
                   !_guestLocked)
            {
                try { await Task.Delay(2000, token).ConfigureAwait(false); }
                catch { return; }
                if (State is not PairingState.Waiting || _guestLocked) return;
                await PublishSignedAsync("h", "ready").ConfigureAwait(false);
            }
        }, token);
    }

    private async Task OnMessageAsync(string mqttTopic, string payload)
    {
        await _signalLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_inboxByTopic.Count > 0 && !_inboxLocked)
            {
                HandleInboxMessage(mqttTopic, payload);
                return;
            }
            HandleMessage(mqttTopic, payload);
        }
        finally
        {
            _signalLock.Release();
        }
    }

    private void HandleInboxMessage(string mqttTopic, string payload)
    {
        if (!_inboxByTopic.TryGetValue(mqttTopic, out var entry)) return;
        var inner = SignalingCrypto.OpenEnvelope(entry.Keys.Enc, payload);
        if (inner is null) return;
        JsonObject? obj;
        try { obj = JsonNode.Parse(inner) as JsonObject; }
        catch { return; }
        if (obj is null) return;
        var eventName = obj["e"]?.GetValue<string>() ?? "";
        var from = obj["r"]?.GetValue<string>() ?? "";
        if (from != "h") return;
        var ts = obj["ts"]?.GetValue<long>() ?? 0;
        var exp = obj["exp"]?.GetValue<long>() ?? 0;
        var nonce = obj["nonce"]?.GetValue<string>() ?? "";
        var mac = obj["mac"]?.GetValue<string>() ?? "";
        var extra = eventName == "manifest"
            ? obj["files"]?.ToJsonString(new JsonSerializerOptions { WriteIndented = false }) ?? ""
            : "";
        var canonical = SignalingCrypto.Canonical(from, eventName, ts, exp, nonce, extra);
        if (!SignalingCrypto.VerifyMac(entry.Keys.Auth, canonical, mac)) return;
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (ts < now - 120 || ts > now + 60 || exp < now) return;
        if (!RememberNonce(nonce)) return;

        if (eventName == "trust-probe")
        {
            if (!TrustProbe.ShouldPong(_inboxByTopic.Keys, mqttTopic)) return;
            _ = ReplyTrustPongAsync(mqttTopic, entry, probeNonce: nonce);
            return;
        }
        if (eventName is not ("ready" or "manifest" or "paired")) return;
        if (eventName == "manifest")
            SetRemoteFiles(ParseManifest(obj));
        if (State is PairingState.Paired or PairingState.Waiting) return;
        _topic = mqttTopic;
        _authKey = entry.Keys.Auth;
        _encKey = entry.Keys.Enc;
        _sessionTopicId = SignalingCrypto.TrustTopicId(entry.Device.PairId);
        _normalizedCode = entry.Device.TrustKeyHex;
        _sessionExpEpochSec = exp;
        var files = eventName == "manifest" ? ParseManifest(obj) : RemoteFiles.ToList();
        SetState(new PairingState.TrustedIncoming(TrustedDevices.DisplayName(entry.Device), files));
    }

    private void HandleMessage(string mqttTopic, string payload)
    {
        if (_role is null || _authKey.Length == 0 || _encKey.Length == 0)
        {
            return;
        }
        if (_topic is not null && mqttTopic != _topic)
        {
            return;
        }
        var inner = SignalingCrypto.OpenEnvelope(_encKey, payload);
        if (inner is null)
        {
            return;
        }
        JsonObject? obj;
        try { obj = JsonNode.Parse(inner) as JsonObject; }
        catch { return; }
        if (obj is null) return;

        var eventName = obj["e"]?.GetValue<string>() ?? "";
        var from = obj["r"]?.GetValue<string>() ?? "";
        var ts = obj["ts"]?.GetValue<long>() ?? 0;
        var exp = obj["exp"]?.GetValue<long>() ?? 0;
        var nonce = obj["nonce"]?.GetValue<string>() ?? "";
        var mac = obj["mac"]?.GetValue<string>() ?? "";

        var extra = eventName switch
        {
            "manifest" => obj["files"]?.ToJsonString(new JsonSerializerOptions { WriteIndented = false }) ?? "",
            "fstart" or "fbin" or "fdone" => MqttFileTransfer.TransferExtra(obj),
            "sdp-offer" or "sdp-answer" => ProtocolPaths.ShortHash(obj["sdp"]?.GetValue<string>() ?? ""),
            "ice" => ProtocolPaths.ShortHash(obj["candidate"]?.GetValue<string>() ?? ""),
            "trust-offer" => SignalingCrypto.TrustOfferMacExtra(
                obj["pairId"]?.GetValue<string>() ?? "",
                obj["trustKey"]?.GetValue<string>() ?? "",
                obj["deviceId"]?.GetValue<string>() ?? "",
                obj["name"]?.GetValue<string>() ?? ""),
            "trust-ack" => SignalingCrypto.TrustAckMacExtra(
                obj["pairId"]?.GetValue<string>() ?? "",
                obj["deviceId"]?.GetValue<string>() ?? "",
                obj["name"]?.GetValue<string>() ?? ""),
            "trust-request" => SignalingCrypto.TrustRequestMacExtra(
                obj["deviceId"]?.GetValue<string>() ?? "",
                obj["name"]?.GetValue<string>() ?? ""),
            "trust-pong" => _trustProbeNonce ?? "",
            _ => ""
        };
        var canonical = SignalingCrypto.Canonical(from, eventName, ts, exp, nonce, extra);
        if (!SignalingCrypto.VerifyMac(_authKey, canonical, mac))
        {
            return;
        }
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (ts < now - 120 || ts > now + 60 || exp < now)
        {
            return;
        }
        if (!RememberNonce(nonce)) return;

        var r = _role;
        switch (eventName)
        {
            case "trust-pong" when r == "host" && from == "g":
                if (!_trustProbePending) return;
                if (!TrustProbe.PongMatchesProbe(_trustProbeNonce ?? "", extra)) return;
                CompleteTrustProbe();
                break;
            case "manifest" when from == "h" && r == "guest":
                if (_manifestFrozen) return;
                SetRemoteFiles(ParseManifest(obj));
                if (State is PairingState.Paired or PairingState.Confirming) _manifestFrozen = true;
                break;
            case "join" when r == "host" && from == "g":
                if (_trustProbePending) return;
                if (_guestLocked) return;
                _guestLocked = true;
                _readyRetryCts?.Cancel();
                _ = PublishSignedAsync("h", "paired");
                _ = PublishManifestAsync();
                if (_skipPhraseConfirm) SetState(new PairingState.Paired());
                else EnterConfirming();
                break;
            case "paired" when r == "guest" && from == "h":
                _joinRetryCts?.Cancel();
                if (RemoteFiles.Count > 0) _manifestFrozen = true;
                if (_skipPhraseConfirm) SetState(new PairingState.Paired());
                else EnterConfirming();
                break;
            case "ready" when r == "guest" && from == "h":
                if (State is PairingState.TrustedIncoming or PairingState.ListeningForTrusted) return;
                _ = PublishSignedAsync("g", "join");
                break;
            case "confirm" when (r == "host" && from == "g") || (r == "guest" && from == "h"):
                _peerConfirmed = true;
                RefreshConfirming();
                MaybeCompletePair();
                break;
            case "sdp-offer" when (r == "guest" && from == "h") || (r == "host" && from == "g"):
                _pendingRemoteOffer = obj["sdp"]?.GetValue<string>();
                break;
            case "sdp-answer" when (r == "host" && from == "g") || (r == "guest" && from == "h"):
                _pendingRemoteAnswer = obj["sdp"]?.GetValue<string>();
                break;
            case "ice" when (r == "host" && from == "g") || (r == "guest" && from == "h"):
            {
                var cand = new IceCandidateDto(
                    string.IsNullOrWhiteSpace(obj["sdpMid"]?.GetValue<string>()) ? null : obj["sdpMid"]!.GetValue<string>(),
                    obj["sdpMLineIndex"]?.GetValue<int>() ?? 0,
                    obj["candidate"]?.GetValue<string>() ?? "");
                if (string.IsNullOrWhiteSpace(cand.Sdp)) return;
                if (_webrtc is not null)
                    _webrtc.AddRemoteIce(cand.SdpMid, cand.SdpMLineIndex, cand.Sdp);
                else
                    lock (_pendingRemoteIce) _pendingRemoteIce.Add(cand);
                break;
            }
            case "xfer-mqtt" when from == "h" && r == "guest":
                _forceMqttRelay = true;
                if (!_transferComplete)
                {
                    CloseWebRtc();
                    _byteMode = ByteTransferMode.Mqtt;
                }
                break;
            case "xfer-ack" when r == "host" && from == "g":
                _mqttTransfer?.MarkPeerAcked();
                break;
            case "xfer-cancel" when (from == "h" && r == "guest") || (from == "g" && r == "host"):
                AbortActiveTransfer(TransferCancelledByPeer);
                break;
            case "fstart" or "fbin" or "fdone" or "xfer-complete" when r == "guest" && from == "h":
                _forceMqttRelay = true;
                if (_byteMode == ByteTransferMode.WebRtc) return;
                if (_byteMode == ByteTransferMode.Undecided)
                {
                    _byteMode = ByteTransferMode.Mqtt;
                    CloseWebRtc();
                }
                EnsureMqttFileTransfer();
                _mqttTransfer!.OnGuestEvent(eventName, obj);
                break;
            case "trust-offer" when r == "guest" && from == "h":
                HandleTrustOffer(obj);
                break;
            case "trust-ack" when r == "host" && from == "g":
                HandleTrustAck(obj);
                break;
            case "trust-request" when (r == "host" && from == "g") || (r == "guest" && from == "h"):
                HandleTrustRequest(obj);
                break;
            case "trust-decline" when (r == "host" && from == "g") || (r == "guest" && from == "h"):
                if (_trustHandshake is TrustHandshakeState.Complete) return;
                _persistPeer = false;
                _persistLocal = false;
                if (!_ephemeralBind)
                {
                    _peerWantsTrust = false;
                    _localWantsTrust = false;
                    _hostSentTrustOffer = false;
                }
                SetTrustHandshake(new TrustHandshakeState.Declined());
                break;
            case "trust-timeout" when (r == "host" && from == "g") || (r == "guest" && from == "h"):
                if (_trustHandshake is TrustHandshakeState.Complete) return;
                _persistLocal = false;
                _persistPeer = false;
                SetTrustHandshake(new TrustHandshakeState.TimedOut());
                break;
        }
    }

    private void HandleTrustOffer(JsonObject obj)
    {
        var offer = new PendingTrustOffer(
            obj["pairId"]?.GetValue<string>() ?? "",
            obj["trustKey"]?.GetValue<string>() ?? "",
            obj["deviceId"]?.GetValue<string>() ?? "",
            obj["name"]?.GetValue<string>() ?? "");
        if (offer.PairId.Length == 0 || offer.TrustKeyHex.Length == 0 || offer.PeerDeviceId.Length == 0)
            return;
        _pendingTrustOffer = offer;
        if (offer.PeerName.Length > 0) _pendingPeerAdvertisedName = offer.PeerName;
        _peerWantsTrust = true;
        if (_localWantsTrust || (State is PairingState.Paired && _ephemeralBind))
            _ = AckAndCompleteAsync(offer);
        else if (State is PairingState.Paired && !_persistLocal)
        {
            // Pair-first: wait for StartEphemeralBind.
        }
        else if (_trustHandshake is not TrustHandshakeState.Complete and not TrustHandshakeState.TimedOut)
        {
            SetTrustHandshake(new TrustHandshakeState.IncomingRequest(
                offer.PeerName.Length > 0 ? offer.PeerName : "the other device"));
        }
    }

    private void HandleTrustAck(JsonObject obj)
    {
        if (!_hostSentTrustOffer) return;
        var pairId = obj["pairId"]?.GetValue<string>() ?? "";
        var peerId = obj["deviceId"]?.GetValue<string>() ?? "";
        var peerName = obj["name"]?.GetValue<string>() ?? "";
        var key = _hostTrustKeyHex;
        if (key is null || pairId.Length == 0 || pairId != _hostPairId || peerId.Length == 0) return;
        if (!_localWantsTrust || !_peerWantsTrust) return;
        ApplyTrustMaterial(new PendingTrustOffer(
            pairId, key, peerId,
            peerName.Length > 0 ? peerName : _pendingPeerAdvertisedName ?? ""));
    }

    private void HandleTrustRequest(JsonObject obj)
    {
        var peerId = obj["deviceId"]?.GetValue<string>() ?? "";
        var peerName = obj["name"]?.GetValue<string>() ?? "";
        if (peerId.Length == 0) return;
        _peerWantsTrust = true;
        _persistPeer = true;
        if (peerName.Length > 0) _pendingPeerAdvertisedName = peerName;
        if (_persistLocal)
            CompletePersistFromEphemeralOrOffer();
        else if (_trustHandshake is not TrustHandshakeState.Complete and not TrustHandshakeState.TimedOut)
        {
            SetTrustHandshake(new TrustHandshakeState.IncomingRequest(
                peerName.Length > 0 ? peerName : "the other device"));
        }
    }

    private async Task RetryTrustOfferAsync()
    {
        for (var i = 0; i < 10; i++)
        {
            await Task.Delay(400).ConfigureAwait(false);
            if (_ephemeralPair is not null) return;
            if (State is not PairingState.Paired) return;
            if (_role != "host") return;
            _hostSentTrustOffer = false;
            await SendTrustOfferIfNeededAsync().ConfigureAwait(false);
        }
    }

    private async Task SendTrustOfferIfNeededAsync()
    {
        if (_role != "host" || _hostSentTrustOffer) return;
        if (!_localWantsTrust || !_peerWantsTrust) return;
        var deviceId = _localDeviceId;
        if (deviceId is null) return;
        var name = _localAdvertisedName ?? "Windows";
        _hostPairId ??= Guid.NewGuid().ToString();
        _hostTrustKeyHex ??= SignalingCrypto.RandomTrustKeyHex();
        var extra = SignalingCrypto.TrustOfferMacExtra(_hostPairId, _hostTrustKeyHex, deviceId, name);
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var exp = _sessionExpEpochSec;
        var nonce = SignalingCrypto.RandomNonce();
        var mac = SignalingCrypto.MacHex(_authKey, SignalingCrypto.Canonical("h", "trust-offer", ts, exp, nonce, extra));
        var inner = new JsonObject
        {
            ["r"] = "h",
            ["e"] = "trust-offer",
            ["ts"] = ts,
            ["exp"] = exp,
            ["nonce"] = nonce,
            ["mac"] = mac,
            ["pairId"] = _hostPairId,
            ["trustKey"] = _hostTrustKeyHex,
            ["deviceId"] = deviceId,
            ["name"] = name
        }.ToJsonString();
        await PublishSealedAsync(inner, 1).ConfigureAwait(false);
        _hostSentTrustOffer = true;
    }

    private async Task AckAndCompleteAsync(PendingTrustOffer offer)
    {
        var deviceId = _localDeviceId;
        if (deviceId is null) return;
        var name = _localAdvertisedName ?? "Windows";
        var extra = SignalingCrypto.TrustAckMacExtra(offer.PairId, deviceId, name);
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var exp = _sessionExpEpochSec;
        var nonce = SignalingCrypto.RandomNonce();
        var mac = SignalingCrypto.MacHex(_authKey, SignalingCrypto.Canonical("g", "trust-ack", ts, exp, nonce, extra));
        var inner = new JsonObject
        {
            ["r"] = "g",
            ["e"] = "trust-ack",
            ["ts"] = ts,
            ["exp"] = exp,
            ["nonce"] = nonce,
            ["mac"] = mac,
            ["pairId"] = offer.PairId,
            ["deviceId"] = deviceId,
            ["name"] = name
        }.ToJsonString();
        await PublishSealedAsync(inner, 1).ConfigureAwait(false);
        ApplyTrustMaterial(offer);
    }

    private async Task PublishTrustRequestAsync()
    {
        var deviceId = _localDeviceId;
        if (deviceId is null || _role is null) return;
        var name = _localAdvertisedName ?? "Windows";
        var roleChar = _role == "host" ? "h" : "g";
        var extra = SignalingCrypto.TrustRequestMacExtra(deviceId, name);
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var exp = _sessionExpEpochSec;
        var nonce = SignalingCrypto.RandomNonce();
        var mac = SignalingCrypto.MacHex(_authKey, SignalingCrypto.Canonical(roleChar, "trust-request", ts, exp, nonce, extra));
        var inner = new JsonObject
        {
            ["r"] = roleChar,
            ["e"] = "trust-request",
            ["ts"] = ts,
            ["exp"] = exp,
            ["nonce"] = nonce,
            ["mac"] = mac,
            ["deviceId"] = deviceId,
            ["name"] = name
        }.ToJsonString();
        await PublishSealedAsync(inner, 1).ConfigureAwait(false);
    }

    private void CompletePersistFromEphemeralOrOffer()
    {
        if (_ephemeralPair is { } e)
        {
            SetTrustHandshake(new TrustHandshakeState.Complete(
                e.PairId, e.TrustKeyHex, e.PeerDeviceId, e.PeerName));
            return;
        }
        if (_localWantsTrust && _peerWantsTrust)
        {
            if (_role == "host") _ = SendTrustOfferIfNeededAsync();
            else if (_pendingTrustOffer is not null) _ = AckAndCompleteAsync(_pendingTrustOffer);
        }
    }

    private void ApplyTrustMaterial(PendingTrustOffer offer)
    {
        _ephemeralPair = new EphemeralPair(offer.PairId, offer.TrustKeyHex, offer.PeerDeviceId, offer.PeerName);
        EphemeralPairChanged?.Invoke(_ephemeralPair);
        if (TrustBindPolicy.PersistToStore(_ephemeralBind, _persistLocal, _persistPeer))
        {
            SetTrustHandshake(new TrustHandshakeState.Complete(
                offer.PairId, offer.TrustKeyHex, offer.PeerDeviceId, offer.PeerName));
        }
    }

    private async Task PublishTrustProbeAsync()
    {
        _trustProbeNonce = await PublishSignedAsync("h", "trust-probe").ConfigureAwait(false);
    }

    private void ScheduleProbeTimeout(int gen)
    {
        _probeCts?.Cancel();
        _probeCts = new CancellationTokenSource();
        var token = _probeCts.Token;
        _ = Task.Run(async () =>
        {
            try { await Task.Delay(TrustProbe.TimeoutMs, token).ConfigureAwait(false); }
            catch { return; }
            if (gen != _sessionGen) return;
            if (!_trustProbePending) return;
            _trustProbePending = false;
            _trustProbeNonce = null;
            SetState(new PairingState.Failed(TrustProbe.FailReason));
        }, token);
    }

    private void CompleteTrustProbe()
    {
        if (!_trustProbePending) return;
        _trustProbePending = false;
        _trustProbeNonce = null;
        _probeCts?.Cancel();
        _ = PublishSignedAsync("h", "ready");
        _ = PublishManifestAsync();
        if (State is not PairingState.Paired and not PairingState.Confirming)
            SetState(new PairingState.Waiting());
    }

    private async Task ReplyTrustPongAsync(string mqttTopic, InboxEntry entry, string probeNonce)
    {
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        _lastProbePongAtMs.TryGetValue(mqttTopic, out var last);
        if (!TrustProbe.AllowProbeReply(last, nowMs)) return;
        _lastProbePongAtMs[mqttTopic] = nowMs;
        var extra = SignalingCrypto.TrustPongMacExtra(probeNonce);
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var exp = _sessionExpEpochSec;
        var nonce = SignalingCrypto.RandomNonce();
        var mac = SignalingCrypto.MacHex(entry.Keys.Auth, SignalingCrypto.Canonical("g", "trust-pong", ts, exp, nonce, extra));
        var inner = new JsonObject
        {
            ["r"] = "g",
            ["e"] = "trust-pong",
            ["ts"] = ts,
            ["exp"] = exp,
            ["nonce"] = nonce,
            ["mac"] = mac
        }.ToJsonString();
        await PublishSealedAsync(inner, 1, mqttTopic, entry.Keys.Enc).ConfigureAwait(false);
    }

    private async Task RunHostTransferAsync(
        IReadOnlyList<LocalShareEntry> entries, bool encryptFileTransfer, CancellationToken ct)
    {
        try
        {
            if (encryptFileTransfer)
            {
                _byteMode = ByteTransferMode.Mqtt;
                await PublishSignedAsync("h", "xfer-mqtt").ConfigureAwait(false);
                await RunMqttHostSendAsync(entries, ct).ConfigureAwait(false);
            }
            else
            {
                var ok = false;
                try { ok = await TryHostWebRtcAsync(entries, ct).ConfigureAwait(false); }
                catch { ok = false; }
                if (ok)
                {
                    _byteMode = ByteTransferMode.WebRtc;
                    await AwaitTransferTerminalAsync(ct).ConfigureAwait(false);
                }
                else
                {
                    CloseWebRtc();
                    _byteMode = ByteTransferMode.Mqtt;
                    await PublishSignedAsync("h", "xfer-mqtt").ConfigureAwait(false);
                    await RunMqttHostSendAsync(entries, ct).ConfigureAwait(false);
                }
            }
        }
        catch (Exception ex)
        {
            FailTransfer(ex.Message);
        }
    }

    private async Task RunGuestTransferAsync(
        IReadOnlyList<SharedFileInfo> expected, string receiveRoot, bool encryptFileTransfer, CancellationToken ct)
    {
        try
        {
            if (encryptFileTransfer || _forceMqttRelay)
            {
                _byteMode = ByteTransferMode.Mqtt;
                await AwaitTransferTerminalAsync(ct).ConfigureAwait(false);
                return;
            }

            var ok = false;
            try { ok = await TryGuestWebRtcAsync(expected, receiveRoot, ct).ConfigureAwait(false); }
            catch { ok = false; }
            if (ok)
            {
                _byteMode = ByteTransferMode.WebRtc;
                await AwaitTransferTerminalAsync(ct).ConfigureAwait(false);
            }
            else
            {
                CloseWebRtc();
                _byteMode = ByteTransferMode.Mqtt;
                await AwaitTransferTerminalAsync(ct).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            FailTransfer(ex.Message);
        }
    }

    private async Task<bool> TryHostWebRtcAsync(IReadOnlyList<LocalShareEntry> entries, CancellationToken ct)
    {
        CloseWebRtc();
        _pendingRemoteOffer = null;
        _pendingRemoteAnswer = null;
        _forceMqttRelay = false;
        var deadline = DateTime.UtcNow.AddMilliseconds(WebrtcBudgetMs);

        // Ask Android (libwebrtc) to create the offer + DataChannel; Windows answers.
        // Keeps the handshake identical to what the shipped Android APK expects.
        await PublishSignedAsync("h", "webrtc-please-offer").ConfigureAwait(false);

        var peer = new WebRtcPeer(isHost: false);
        _webrtc = peer;
        WireLocalIce(peer, "h");

        string? offer = null;
        while (DateTime.UtcNow < deadline && !_forceMqttRelay)
        {
            ct.ThrowIfCancellationRequested();
            offer = _pendingRemoteOffer;
            if (offer is not null) break;
            await Task.Delay(50, ct).ConfigureAwait(false);
        }
        if (offer is null) return false;

        string answer;
        try
        {
            answer = await peer.ApplyRemoteOfferAndCreateAnswerAsync(offer, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch
        {
            return false;
        }
        await PublishSdpAsync("h", "sdp-answer", answer).ConfigureAwait(false);
        _ = peer.AwaitIceGatheringCompleteAsync(TimeSpan.FromSeconds(8), ct)
            .ContinueWith(_ => PublishSignedAsync("h", "ice-done"), TaskScheduler.Default);
        FlushPendingRemoteIce(peer);

        var remain = deadline - DateTime.UtcNow;
        if (remain <= TimeSpan.Zero) return false;
        if (!await peer.AwaitDataChannelOpenAsync(remain, ct).ConfigureAwait(false)) return false;

        _byteMode = ByteTransferMode.WebRtc;
        var dc = new DataChannelTransfer(
            peer,
            p => ProgressChanged?.Invoke(p),
            s => { SavedFiles = s; SavedFilesChanged?.Invoke(s); },
            () => { _transferComplete = true; TransferCompleted?.Invoke(); },
            FailTransfer);
        _dcTransfer = dc;
        _ = dc.StartHostSendAsync(entries, ct);
        return true;
    }

    private async Task<bool> TryGuestWebRtcAsync(
        IReadOnlyList<SharedFileInfo> expected, string receiveRoot, CancellationToken ct)
    {
        CloseWebRtc();
        _forceMqttRelay = false;
        var deadline = DateTime.UtcNow.AddMilliseconds(WebrtcBudgetMs);
        var peer = new WebRtcPeer(isHost: false);
        _webrtc = peer;
        WireLocalIce(peer, "g");

        var sessionId = _sessionTopicId ?? SignalingCrypto.TopicId(_normalizedCode!);
        var sink = Path.Combine(receiveRoot, sessionId);
        var dc = new DataChannelTransfer(
            peer,
            p => ProgressChanged?.Invoke(p),
            s => { SavedFiles = s; SavedFilesChanged?.Invoke(s); },
            () => { _transferComplete = true; TransferCompleted?.Invoke(); },
            FailTransfer);
        _dcTransfer = dc;
        dc.PrepareGuestSink(sink, expected);
        _ = dc.StartGuestReceiveAsync(ct);

        string? offer = null;
        while (DateTime.UtcNow < deadline && !_forceMqttRelay)
        {
            ct.ThrowIfCancellationRequested();
            offer = _pendingRemoteOffer;
            if (offer is not null) break;
            await Task.Delay(50, ct).ConfigureAwait(false);
        }
        if (offer is null) return false;

        var answer = await peer.ApplyRemoteOfferAndCreateAnswerAsync(offer, ct).ConfigureAwait(false);
        await PublishSdpAsync("g", "sdp-answer", answer).ConfigureAwait(false);
        _ = peer.AwaitIceGatheringCompleteAsync(TimeSpan.FromSeconds(8), ct)
            .ContinueWith(_ => PublishSignedAsync("g", "ice-done"), TaskScheduler.Default);
        FlushPendingRemoteIce(peer);

        while (DateTime.UtcNow < deadline && !_forceMqttRelay)
        {
            if (await peer.AwaitDataChannelOpenAsync(TimeSpan.FromMilliseconds(200), ct).ConfigureAwait(false))
            {
                _byteMode = ByteTransferMode.WebRtc;
                return true;
            }
        }
        return false;
    }

    private void WireLocalIce(WebRtcPeer peer, string roleChar)
    {
        peer.LocalIce += ice => _ = PublishIceAsync(roleChar, ice);
    }

    private void FlushPendingRemoteIce(WebRtcPeer peer)
    {
        List<IceCandidateDto> copy;
        lock (_pendingRemoteIce)
        {
            copy = _pendingRemoteIce.ToList();
            _pendingRemoteIce.Clear();
        }
        foreach (var c in copy)
            peer.AddRemoteIce(c.SdpMid, c.SdpMLineIndex, c.Sdp);
    }

    private async Task RunMqttHostSendAsync(IReadOnlyList<LocalShareEntry> entries, CancellationToken ct)
    {
        EnsureMqttFileTransfer();
        await _mqttTransfer!.StartHostSendAsync(entries, ct).ConfigureAwait(false);
        await AwaitTransferTerminalAsync(ct).ConfigureAwait(false);
    }

    private async Task AwaitTransferTerminalAsync(CancellationToken ct)
    {
        var deadline = DateTime.UtcNow.AddMinutes(30);
        while (DateTime.UtcNow < deadline && !ct.IsCancellationRequested)
        {
            if (_transferComplete || _transferFailed is not null) return;
            await Task.Delay(200, ct).ConfigureAwait(false);
        }
        if (!_transferComplete && _transferFailed is null)
            FailTransfer("Transfer timed out");
    }

    private void EnsureMqttFileTransfer()
    {
        if (_mqttTransfer is not null) return;
        _mqttTransfer = new MqttFileTransfer(
            (json, qos) => PublishSealedAsync(json, qos),
            () => _authKey,
            () => _sessionExpEpochSec,
            () => _role is not null && _authKey.Length > 0,
            p => ProgressChanged?.Invoke(p),
            s => { SavedFiles = s; SavedFilesChanged?.Invoke(s); },
            () => { _transferComplete = true; TransferCompleted?.Invoke(); },
            FailTransfer);
    }

    private void CloseWebRtc()
    {
        _dcTransfer?.Reset();
        _dcTransfer = null;
        _webrtc?.Dispose();
        _webrtc = null;
    }

    private void AbortActiveTransfer(string reason)
    {
        if (_transferComplete) return;
        FailTransfer(reason);
        _dcTransfer?.SendCancel();
        _dcTransfer?.Abort(reason);
        _mqttTransfer?.Abort(reason);
        CloseWebRtc();
    }

    private List<SharedFileInfo> ParseManifest(JsonObject obj)
    {
        var files = obj["files"] as JsonArray;
        if (files is null) return new List<SharedFileInfo>();
        var list = new List<SharedFileInfo>();
        foreach (var item in files)
        {
            if (item is not JsonObject f) continue;
            var name = ProtocolPaths.SanitizeWirePath(f["n"]?.GetValue<string>() ?? "");
            if (name is null) continue;
            list.Add(new SharedFileInfo(name, f["s"]?.GetValue<long>() ?? -1));
        }
        return list;
    }

    private async Task PublishManifestAsync()
    {
        if (_localManifest.Count == 0) return;
        var filesArr = new JsonArray();
        foreach (var item in _localManifest)
        {
            var path = ProtocolPaths.SanitizeWirePath(item.Name);
            if (path is null) continue;
            filesArr.Add(new JsonObject { ["n"] = path.Length > 180 ? path[..180] : path, ["s"] = item.SizeBytes });
        }
        var filesStr = filesArr.ToJsonString(new JsonSerializerOptions { WriteIndented = false });
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var exp = _sessionExpEpochSec;
        var nonce = SignalingCrypto.RandomNonce();
        var mac = SignalingCrypto.MacHex(_authKey, SignalingCrypto.Canonical("h", "manifest", ts, exp, nonce, filesStr));
        var inner = new JsonObject
        {
            ["r"] = "h",
            ["e"] = "manifest",
            ["ts"] = ts,
            ["exp"] = exp,
            ["nonce"] = nonce,
            ["mac"] = mac,
            ["files"] = filesArr
        }.ToJsonString(new JsonSerializerOptions { WriteIndented = false });
        await PublishSealedAsync(inner, 1).ConfigureAwait(false);
    }

    private async Task PublishSdpAsync(string roleChar, string eventName, string sdp)
    {
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var exp = _sessionExpEpochSec;
        var nonce = SignalingCrypto.RandomNonce();
        var extra = ProtocolPaths.ShortHash(sdp);
        var mac = SignalingCrypto.MacHex(_authKey, SignalingCrypto.Canonical(roleChar, eventName, ts, exp, nonce, extra));
        var inner = new JsonObject
        {
            ["r"] = roleChar,
            ["e"] = eventName,
            ["ts"] = ts,
            ["exp"] = exp,
            ["nonce"] = nonce,
            ["mac"] = mac,
            ["sdp"] = sdp
        }.ToJsonString();
        await PublishSealedAsync(inner, 1).ConfigureAwait(false);
    }

    private async Task PublishIceAsync(string roleChar, IceCandidateDto ice)
    {
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var exp = _sessionExpEpochSec;
        var nonce = SignalingCrypto.RandomNonce();
        var extra = ProtocolPaths.ShortHash(ice.Sdp);
        var mac = SignalingCrypto.MacHex(_authKey, SignalingCrypto.Canonical(roleChar, "ice", ts, exp, nonce, extra));
        var inner = new JsonObject
        {
            ["r"] = roleChar,
            ["e"] = "ice",
            ["ts"] = ts,
            ["exp"] = exp,
            ["nonce"] = nonce,
            ["mac"] = mac,
            ["candidate"] = ice.Sdp,
            ["sdpMid"] = ice.SdpMid ?? "",
            ["sdpMLineIndex"] = ice.SdpMLineIndex
        }.ToJsonString();
        await PublishSealedAsync(inner, 1).ConfigureAwait(false);
    }

    private async Task<string> PublishSignedAsync(string roleChar, string eventName)
    {
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var exp = _sessionExpEpochSec;
        var nonce = SignalingCrypto.RandomNonce();
        var mac = SignalingCrypto.MacHex(_authKey, SignalingCrypto.Canonical(roleChar, eventName, ts, exp, nonce));
        var inner = new JsonObject
        {
            ["r"] = roleChar,
            ["e"] = eventName,
            ["ts"] = ts,
            ["exp"] = exp,
            ["nonce"] = nonce,
            ["mac"] = mac
        }.ToJsonString();
        await PublishSealedAsync(inner, 1).ConfigureAwait(false);
        return nonce;
    }

    private async Task PublishSealedAsync(
        string innerJson, int qos, string? topicOverride = null, byte[]? encOverride = null)
    {
        var enc = encOverride ?? _encKey;
        var topic = topicOverride ?? _topic;
        if (enc.Length == 0 || _client is null || topic is null || !_client.IsConnected) return;
        var envelope = SignalingCrypto.SealEnvelope(enc, innerJson);
        var msg = new MqttApplicationMessageBuilder()
            .WithTopic(topic)
            .WithPayload(envelope)
            .WithQualityOfServiceLevel(qos == 0
                ? MqttQualityOfServiceLevel.AtMostOnce
                : MqttQualityOfServiceLevel.AtLeastOnce)
            .Build();
        await _client.PublishAsync(msg).ConfigureAwait(false);
    }

    private bool RememberNonce(string nonce) => _seenNonces.TryRemember(nonce);

    private void EnterConfirming()
    {
        _joinRetryCts?.Cancel();
        var code = _normalizedCode;
        if (code is null) return;
        SetState(new PairingState.Confirming(SignalingCrypto.ConfirmPhrase(code), _localConfirmed, _peerConfirmed));
    }

    private void RefreshConfirming()
    {
        if (State is PairingState.Confirming c)
            SetState(c with { LocalConfirmed = _localConfirmed, PeerConfirmed = _peerConfirmed });
    }

    private void MaybeCompletePair()
    {
        if (_localConfirmed && _peerConfirmed)
            SetState(new PairingState.Paired());
    }

    private void SetState(PairingState state)
    {
        State = state;
        StateChanged?.Invoke(state);
    }

    private void SetTrustHandshake(TrustHandshakeState state)
    {
        _trustHandshake = state;
        TrustHandshakeChanged?.Invoke(state);
    }

    private void SetRemoteFiles(IReadOnlyList<SharedFileInfo> files)
    {
        RemoteFiles = files;
        RemoteFilesChanged?.Invoke(files);
    }

    private void FailTransfer(string reason)
    {
        if (_transferFailed is not null) return;
        _transferFailed = reason;
        TransferFailed?.Invoke(reason);
    }
}
