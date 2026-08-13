using System.Collections.Concurrent;
using SIPSorcery.Net;

namespace EasyShare.Protocol;

/// <summary>STUN-only WebRTC peer with a single ordered DataChannel (label easyshare).</summary>
public sealed class WebRtcPeer : IDisposable
{
    public const string DcLabel = "easyshare";

    private static readonly string[] StunServers =
    [
        "stun:stun.l.google.com:19302",
        "stun:stun1.l.google.com:19302",
        "stun:stun.cloudflare.com:3478"
    ];

    private readonly bool _isHost;
    private readonly RTCPeerConnection _pc;
    private RTCDataChannel? _dc;
    private readonly ConcurrentQueue<IceCandidateDto> _localIce = new();
    private readonly TaskCompletionSource<bool> _iceGatherDone = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<bool> _dcOpen = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly ConcurrentQueue<byte[]> _incoming = new();
    private readonly SemaphoreSlim _incomingSignal = new(0);
    private readonly List<RTCIceCandidateInit> _pendingRemoteIce = new();
    private bool _remoteDescSet;
    private bool _disposed;
    private string? _error;

    public event Action<IceCandidateDto>? LocalIce;
    public event Action<byte[]>? MessageReceived;

    public WebRtcPeer(bool isHost)
    {
        _isHost = isHost;
        var config = new RTCConfiguration
        {
            iceServers = StunServers.Select(u => new RTCIceServer { urls = u }).ToList()
        };
        _pc = new RTCPeerConnection(config);
        _pc.onicecandidate += candidate =>
        {
            if (candidate is null || string.IsNullOrWhiteSpace(candidate.candidate))
            {
                _iceGatherDone.TrySetResult(true);
                return;
            }
            var dto = new IceCandidateDto(
                candidate.sdpMid,
                candidate.sdpMLineIndex,
                candidate.candidate);
            _localIce.Enqueue(dto);
            LocalIce?.Invoke(dto);
        };
        _pc.onconnectionstatechange += state =>
        {
            if (state == RTCPeerConnectionState.failed)
                _error = "ICE connection failed";
        };
        _pc.ondatachannel += dc => AttachDataChannel(dc);

        if (_isHost)
        {
            var init = new RTCDataChannelInit { ordered = true };
            // createDataChannel is sync in SIPSorcery
            var dc = _pc.createDataChannel(DcLabel, init).GetAwaiter().GetResult();
            AttachDataChannel(dc);
        }
    }

    public string? Error => _error;
    public bool IsDataChannelOpen => _dcOpen.Task.IsCompletedSuccessfully && _dcOpen.Task.Result;

    public async Task<string> CreateOfferSdpAsync(CancellationToken ct = default)
    {
        var offer = _pc.createOffer(null);
        await _pc.setLocalDescription(offer).ConfigureAwait(false);
        _ = WaitGatheringAsync(ct);
        return offer.sdp ?? throw new InvalidOperationException("Empty offer SDP");
    }

    public async Task<string> ApplyRemoteOfferAndCreateAnswerAsync(string remoteSdp, CancellationToken ct = default)
    {
        var remote = new RTCSessionDescriptionInit { type = RTCSdpType.offer, sdp = remoteSdp };
        var setResult = _pc.setRemoteDescription(remote);
        if (setResult != SetDescriptionResultEnum.OK)
            throw new InvalidOperationException("setRemoteDescription(offer) failed: " + setResult);
        MarkRemoteSet();
        var answer = _pc.createAnswer(null);
        await _pc.setLocalDescription(answer).ConfigureAwait(false);
        _ = WaitGatheringAsync(ct);
        return answer.sdp ?? throw new InvalidOperationException("Empty answer SDP");
    }

    public Task ApplyRemoteAnswerAsync(string remoteSdp)
    {
        var remote = new RTCSessionDescriptionInit { type = RTCSdpType.answer, sdp = remoteSdp };
        var setResult = _pc.setRemoteDescription(remote);
        if (setResult != SetDescriptionResultEnum.OK)
            throw new InvalidOperationException("setRemoteDescription(answer) failed: " + setResult);
        MarkRemoteSet();
        return Task.CompletedTask;
    }

    public void AddRemoteIce(string? sdpMid, int sdpMLineIndex, string candidate)
    {
        if (_disposed || string.IsNullOrWhiteSpace(candidate)) return;
        var init = new RTCIceCandidateInit
        {
            candidate = candidate,
            sdpMid = sdpMid,
            sdpMLineIndex = (ushort)Math.Clamp(sdpMLineIndex, 0, ushort.MaxValue)
        };
        lock (_pendingRemoteIce)
        {
            if (!_remoteDescSet)
            {
                _pendingRemoteIce.Add(init);
                return;
            }
        }
        _pc.addIceCandidate(init);
    }

    public async Task<bool> AwaitDataChannelOpenAsync(TimeSpan timeout, CancellationToken ct = default)
    {
        if (_error != null) return false;
        if (IsDataChannelOpen) return true;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(timeout);
        try
        {
            await _dcOpen.Task.WaitAsync(linked.Token).ConfigureAwait(false);
            return IsDataChannelOpen;
        }
        catch
        {
            return false;
        }
    }

    public async Task AwaitIceGatheringCompleteAsync(TimeSpan timeout, CancellationToken ct = default)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(timeout);
        try { await _iceGatherDone.Task.WaitAsync(linked.Token).ConfigureAwait(false); }
        catch { /* best-effort */ }
    }

    public bool Send(byte[] bytes)
    {
        if (_dc is null || _dc.readyState != RTCDataChannelState.open) return false;
        try
        {
            _dc.send(bytes);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> AwaitSendBufferLowAsync(long threshold = 256L * 1024L, TimeSpan? timeout = null, CancellationToken ct = default)
    {
        // SIPSorcery does not expose bufferedAmount like libwebrtc; yield briefly.
        await Task.Delay(5, ct).ConfigureAwait(false);
        return _dc?.readyState == RTCDataChannelState.open;
    }

    public async IAsyncEnumerable<byte[]> IncomingAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        while (!ct.IsCancellationRequested && !_disposed)
        {
            while (_incoming.TryDequeue(out var msg))
                yield return msg;
            try
            {
                await _incomingSignal.WaitAsync(200, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                yield break;
            }
        }
    }

    private void AttachDataChannel(RTCDataChannel dc)
    {
        _dc = dc;
        dc.onopen += () => _dcOpen.TrySetResult(true);
        dc.onmessage += (_, _, data) =>
        {
            var copy = data.ToArray();
            _incoming.Enqueue(copy);
            _incomingSignal.Release();
            MessageReceived?.Invoke(copy);
        };
        if (dc.readyState == RTCDataChannelState.open)
            _dcOpen.TrySetResult(true);
    }

    private void MarkRemoteSet()
    {
        List<RTCIceCandidateInit> pending;
        lock (_pendingRemoteIce)
        {
            _remoteDescSet = true;
            pending = _pendingRemoteIce.ToList();
            _pendingRemoteIce.Clear();
        }
        foreach (var c in pending)
            _pc.addIceCandidate(c);
    }

    private async Task WaitGatheringAsync(CancellationToken ct)
    {
        try
        {
            // SIPSorcery signals end-of-candidates with a null candidate; also timeout.
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linked.CancelAfter(TimeSpan.FromSeconds(8));
            await _iceGatherDone.Task.WaitAsync(linked.Token).ConfigureAwait(false);
        }
        catch
        {
            _iceGatherDone.TrySetResult(true);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { _dc?.close(); } catch { /* ignore */ }
        try { _pc.Close("dispose"); } catch { /* ignore */ }
        try { _pc.Dispose(); } catch { /* ignore */ }
        _dcOpen.TrySetResult(false);
        _iceGatherDone.TrySetResult(true);
        _incomingSignal.Release();
    }
}
