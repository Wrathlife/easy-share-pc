using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using MQTTnet;
using MQTTnet.Client;
using MQTTnet.Protocol;

namespace EasyShare.Protocol;

/// <summary>
/// Internet pairing + encrypted MQTT signaling.
/// File bytes: WebRTC DataChannel by default; MQTT AES when encrypt is on or WebRTC fails (~18s).
/// </summary>
public sealed class InternetSession : IAsyncDisposable
{
    public const string BrokerHost = "broker.emqx.io";
    public const int BrokerPort = 8883;
    public const long SessionTtlSec = 10 * 60;
    public const int WebrtcBudgetMs = 18_000;

    private enum ByteTransferMode { Undecided, WebRtc, Mqtt }

    private readonly object _gate = new();
    private IMqttClient? _client;
    private string? _topic;
    private string? _role;
    private string? _normalizedCode;
    private byte[] _authKey = Array.Empty<byte>();
    private byte[] _encKey = Array.Empty<byte>();
    private long _sessionExpEpochSec;
    private bool _guestLocked;
    private bool _manifestFrozen;
    private bool _localConfirmed;
    private bool _peerConfirmed;
    private bool _forceMqttRelay;
    private ByteTransferMode _byteMode = ByteTransferMode.Undecided;
    private bool _encryptFileTransfer;
    private List<SharedFileInfo> _localManifest = new();
    private readonly ConcurrentQueue<string> _seenNonces = new();
    private int _seenNonceCount;
    private string? _pendingRemoteOffer;
    private string? _pendingRemoteAnswer;
    private readonly List<IceCandidateDto> _pendingRemoteIce = new();
    private WebRtcPeer? _webrtc;
    private DataChannelTransfer? _dcTransfer;
    private MqttFileTransfer? _mqttTransfer;
    private CancellationTokenSource? _sessionCts;
    private CancellationTokenSource? _joinRetryCts;
    private int _sessionGen;
    private bool _transferComplete;
    private string? _transferFailed;
    private IReadOnlyList<LocalShareEntry> _hostEntries = Array.Empty<LocalShareEntry>();
    private string? _guestReceiveRoot;

    public event Action<PairingState>? StateChanged;
    public event Action<IReadOnlyList<SharedFileInfo>>? RemoteFilesChanged;
    public event Action<TransferProgress?>? ProgressChanged;
    public event Action<IReadOnlyList<SavedFileRecord>>? SavedFilesChanged;
    public event Action? TransferCompleted;
    public event Action<string>? TransferFailed;

    public PairingState State { get; private set; } = new PairingState.Idle();
    public IReadOnlyList<SharedFileInfo> RemoteFiles { get; private set; } = Array.Empty<SharedFileInfo>();
    public IReadOnlyList<SavedFileRecord> SavedFiles { get; private set; } = Array.Empty<SavedFileRecord>();
    public bool IsTransferComplete => _transferComplete;

    public async Task StartHostAsync(string code, IReadOnlyList<SharedFileInfo> files, CancellationToken ct = default)
    {
        _localManifest = files.Take(ProtocolPaths.MaxManifestFiles).ToList();
        await StartAsync(code, "host", ct).ConfigureAwait(false);
    }

    public async Task StartGuestAsync(string code, CancellationToken ct = default)
    {
        _localManifest = new List<SharedFileInfo>();
        SetRemoteFiles(Array.Empty<SharedFileInfo>());
        await StartAsync(code, "guest", ct).ConfigureAwait(false);
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

    public async Task StartHostFileTransferAsync(
        IReadOnlyList<LocalShareEntry> entries,
        bool encryptFileTransfer,
        CancellationToken ct = default)
    {
        _encryptFileTransfer = encryptFileTransfer;
        _hostEntries = entries;
        _transferComplete = false;
        _transferFailed = null;
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

    public async Task PrepareGuestFileSinkAsync(
        string receiveRoot,
        IReadOnlyList<SharedFileInfo> expected,
        bool encryptFileTransfer,
        bool beginTransfer,
        CancellationToken ct = default)
    {
        _encryptFileTransfer = encryptFileTransfer;
        _guestReceiveRoot = receiveRoot;
        EnsureMqttFileTransfer();
        _mqttTransfer!.PrepareGuestSink(receiveRoot, expected);
        if (!beginTransfer) return;

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

    public async Task StopAsync()
    {
        Interlocked.Increment(ref _sessionGen);
        _joinRetryCts?.Cancel();
        _sessionCts?.Cancel();
        CloseWebRtc();
        _mqttTransfer?.Reset();
        _mqttTransfer = null;
        if (_client is not null)
        {
            try { if (_client.IsConnected) await _client.DisconnectAsync().ConfigureAwait(false); } catch { /* ignore */ }
            _client.Dispose();
            _client = null;
        }
        _topic = null;
        _role = null;
        _normalizedCode = null;
        _authKey = Array.Empty<byte>();
        _encKey = Array.Empty<byte>();
        _guestLocked = false;
        _manifestFrozen = false;
        _localConfirmed = false;
        _peerConfirmed = false;
        _forceMqttRelay = false;
        _byteMode = ByteTransferMode.Undecided;
        _pendingRemoteOffer = null;
        _pendingRemoteAnswer = null;
        lock (_pendingRemoteIce) _pendingRemoteIce.Clear();
        SetState(new PairingState.Idle());
    }

    public ValueTask DisposeAsync() => new(StopAsync());

    private async Task StartAsync(string code, string role, CancellationToken ct)
    {
        await StopAsync().ConfigureAwait(false);
        var normalized = PairingCode.Normalize(code);
        if (!PairingCode.IsValidShort(normalized))
        {
            SetState(new PairingState.Failed("Invalid share code format"));
            return;
        }
        var gen = Interlocked.Increment(ref _sessionGen);
        _sessionCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _role = role;
        _normalizedCode = normalized;
        _sessionExpEpochSec = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + SessionTtlSec;
        _topic = $"easyshare/v1/{SignalingCrypto.TopicId(normalized)}";
        SetState(new PairingState.Connecting());

        var keys = SignalingCrypto.SessionKeysFrom(normalized);
        if (gen != _sessionGen) return;
        _authKey = keys.Auth;
        _encKey = keys.Enc;

        var factory = new MqttFactory();
        var client = factory.CreateMqttClient();
        _client = client;
        client.ApplicationMessageReceivedAsync += e =>
        {
            var payload = Encoding.UTF8.GetString(e.ApplicationMessage.PayloadSegment);
            _ = Task.Run(() => OnMessage(payload));
            return Task.CompletedTask;
        };
        client.ConnectedAsync += async _ =>
        {
            if (gen != _sessionGen) return;
            await OnConnectedAsync(gen).ConfigureAwait(false);
        };

        var options = new MqttClientOptionsBuilder()
            .WithTcpServer(BrokerHost, BrokerPort)
            .WithClientId($"es-{role[0]}-{Guid.NewGuid():N}")
            .WithTlsOptions(o => o.UseTls())
            .WithCleanSession()
            .WithKeepAlivePeriod(TimeSpan.FromSeconds(20))
            .WithTimeout(TimeSpan.FromSeconds(20))
            .WithProtocolVersion(MQTTnet.Formatter.MqttProtocolVersion.V311)
            .Build();

        try
        {
            await client.ConnectAsync(options, _sessionCts.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            if (gen != _sessionGen) return;
            SetState(new PairingState.Failed(ex.Message));
        }
    }

    private async Task OnConnectedAsync(int gen)
    {
        if (gen != _sessionGen || _client is null || _topic is null || _role is null) return;
        await _client.SubscribeAsync(_topic, MqttQualityOfServiceLevel.AtLeastOnce).ConfigureAwait(false);
        if (_role == "host")
        {
            await PublishSignedAsync("h", "ready").ConfigureAwait(false);
            await PublishManifestAsync().ConfigureAwait(false);
            if (State is not PairingState.Paired and not PairingState.Confirming)
                SetState(new PairingState.Waiting());
        }
        else
        {
            await PublishSignedAsync("g", "join").ConfigureAwait(false);
            if (State is not PairingState.Paired and not PairingState.Confirming)
                SetState(new PairingState.Waiting());
            _joinRetryCts?.Cancel();
            _joinRetryCts = new CancellationTokenSource();
            var token = _joinRetryCts.Token;
            _ = Task.Run(async () =>
            {
                while (!token.IsCancellationRequested &&
                       State is not PairingState.Paired and not PairingState.Confirming and not PairingState.Failed)
                {
                    await Task.Delay(2000, token).ConfigureAwait(false);
                    if (State is PairingState.Paired or PairingState.Confirming or PairingState.Failed) return;
                    await PublishSignedAsync("g", "join").ConfigureAwait(false);
                }
            }, token);
        }
    }

    private void OnMessage(string payload)
    {
        if (_role is null || _authKey.Length == 0 || _encKey.Length == 0) return;
        var inner = SignalingCrypto.OpenEnvelope(_encKey, payload);
        if (inner is null) return;
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
            _ => ""
        };
        var canonical = SignalingCrypto.Canonical(from, eventName, ts, exp, nonce, extra);
        if (!SignalingCrypto.VerifyMac(_authKey, canonical, mac)) return;
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (ts < now - 120 || ts > now + 60 || exp < now) return;
        if (!string.IsNullOrWhiteSpace(nonce))
        {
            if (_seenNonces.Contains(nonce)) return;
            _seenNonces.Enqueue(nonce);
            if (Interlocked.Increment(ref _seenNonceCount) > 64)
            {
                _seenNonces.TryDequeue(out _);
                Interlocked.Decrement(ref _seenNonceCount);
            }
        }

        var r = _role;
        switch (eventName)
        {
            case "manifest" when from == "h" && r == "guest":
                if (_manifestFrozen) return;
                SetRemoteFiles(ParseManifest(obj));
                if (State is PairingState.Paired or PairingState.Confirming) _manifestFrozen = true;
                break;
            case "join" when r == "host" && from == "g":
                if (_guestLocked) return;
                _guestLocked = true;
                _ = PublishSignedAsync("h", "paired");
                _ = PublishManifestAsync();
                EnterConfirming();
                break;
            case "paired" when r == "guest" && from == "h":
                _joinRetryCts?.Cancel();
                if (RemoteFiles.Count > 0) _manifestFrozen = true;
                EnterConfirming();
                break;
            case "ready" when r == "guest" && from == "h":
                _ = PublishSignedAsync("g", "join");
                break;
            case "confirm" when (r == "host" && from == "g") || (r == "guest" && from == "h"):
                _peerConfirmed = true;
                RefreshConfirming();
                MaybeCompletePair();
                break;
            case "sdp-offer" when r == "guest" && from == "h":
                _pendingRemoteOffer = obj["sdp"]?.GetValue<string>();
                break;
            case "sdp-answer" when r == "host" && from == "g":
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
            case "fstart" or "fbin" or "fdone" or "xfer-complete" when r == "guest" && from == "h":
                if (_byteMode == ByteTransferMode.WebRtc) return;
                if (_byteMode == ByteTransferMode.Undecided)
                {
                    _byteMode = ByteTransferMode.Mqtt;
                    CloseWebRtc();
                }
                EnsureMqttFileTransfer();
                _mqttTransfer!.OnGuestEvent(eventName, obj);
                break;
        }
    }

    private async Task<bool> TryHostWebRtcAsync(IReadOnlyList<LocalShareEntry> entries, CancellationToken ct)
    {
        CloseWebRtc();
        _pendingRemoteAnswer = null;
        _forceMqttRelay = false;
        var deadline = DateTime.UtcNow.AddMilliseconds(WebrtcBudgetMs);
        var peer = new WebRtcPeer(isHost: true);
        _webrtc = peer;
        WireLocalIce(peer, "h");

        var offer = await peer.CreateOfferSdpAsync(ct).ConfigureAwait(false);
        await PublishSdpAsync("h", "sdp-offer", offer).ConfigureAwait(false);
        _ = peer.AwaitIceGatheringCompleteAsync(TimeSpan.FromSeconds(8), ct)
            .ContinueWith(_ => PublishSignedAsync("h", "ice-done"), TaskScheduler.Default);

        string? answer = null;
        while (DateTime.UtcNow < deadline && !_forceMqttRelay)
        {
            ct.ThrowIfCancellationRequested();
            answer = _pendingRemoteAnswer;
            if (answer is not null) break;
            await Task.Delay(50, ct).ConfigureAwait(false);
        }
        if (answer is null) return false;

        await peer.ApplyRemoteAnswerAsync(answer).ConfigureAwait(false);
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

        var sessionId = SignalingCrypto.TopicId(_normalizedCode!);
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
        {
            if (SavedFiles.Count > 0) { _transferComplete = true; TransferCompleted?.Invoke(); }
            else FailTransfer("Transfer timed out");
        }
    }

    private void EnsureMqttFileTransfer()
    {
        if (_mqttTransfer is not null) return;
        _mqttTransfer = new MqttFileTransfer(
            PublishSealedAsync,
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

    private async Task PublishSignedAsync(string roleChar, string eventName)
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
    }

    private async Task PublishSealedAsync(string innerJson, int qos)
    {
        if (_encKey.Length == 0 || _client is null || _topic is null || !_client.IsConnected) return;
        var envelope = SignalingCrypto.SealEnvelope(_encKey, innerJson);
        var msg = new MqttApplicationMessageBuilder()
            .WithTopic(_topic)
            .WithPayload(envelope)
            .WithQualityOfServiceLevel(qos == 0
                ? MqttQualityOfServiceLevel.AtMostOnce
                : MqttQualityOfServiceLevel.AtLeastOnce)
            .Build();
        await _client.PublishAsync(msg).ConfigureAwait(false);
    }

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

    private void SetRemoteFiles(IReadOnlyList<SharedFileInfo> files)
    {
        RemoteFiles = files;
        RemoteFilesChanged?.Invoke(files);
    }

    private void FailTransfer(string reason)
    {
        _transferFailed = reason;
        TransferFailed?.Invoke(reason);
    }
}
