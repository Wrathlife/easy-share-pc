using System.Collections.Concurrent;
using System.Reflection;
using DataChannelDotnet;
using DataChannelDotnet.Bindings;
using DataChannelDotnet.Data;
using DataChannelDotnet.Impl;

namespace EasyShare.Protocol;

/// <summary>
/// STUN-only WebRTC peer with a single ordered DataChannel (label easyshare),
/// backed by libdatachannel (DataChannelDotnet). Replaced SIPSorcery, whose
/// managed SCTP capped sends at well under 1 MB/s.
/// </summary>
public sealed class WebRtcPeer : IDisposable
{
    public const string DcLabel = "easyshare";

    private static readonly string[] StunServers =
    [
        "stun:stun.l.google.com:19302",
        "stun:stun1.l.google.com:19302",
        "stun:stun.cloudflare.com:3478"
    ];

    /// <summary>Native channel id for Rtc.rtcGetBufferedAmount (wrapper doesn't expose it).</summary>
    private static readonly FieldInfo? ChannelIdField =
        typeof(RtcDataChannel).GetField("_channelId", BindingFlags.NonPublic | BindingFlags.Instance);

    private readonly RtcPeerConnection _pc;
    private IRtcDataChannel? _dc;
    private volatile int _dcChannelId = -1;
    private readonly ConcurrentQueue<IceCandidateDto> _localIce = new();
    private readonly TaskCompletionSource<bool> _iceGatherDone = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<bool> _dcOpen = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly ConcurrentQueue<byte[]> _incoming = new();
    private readonly SemaphoreSlim _incomingSignal = new(0);
    private readonly List<IceCandidateDto> _pendingRemoteIce = new();
    private bool _remoteDescSet;
    private volatile bool _disposed;
    private string? _error;
    private int _remoteMaxMessageSize = DcChunkLimits.DefaultMaxMessageSize;
    /// <summary>Fallback pacing counter if the native bufferedAmount is unavailable.</summary>
    private long _bytesSincePause;

    public event Action<IceCandidateDto>? LocalIce;
    public event Action<byte[]>? MessageReceived;

    public WebRtcPeer(bool isHost)
    {
        var config = new RtcPeerConfiguration
        {
            IceServers = StunServers.ToList(),
            MaxMessageSize = DcChunkLimits.LocalMaxMessageSize
        };
        _pc = new RtcPeerConnection(config);
        _pc.OnCandidateSafe += (_, cand) =>
        {
            if (string.IsNullOrWhiteSpace(cand.Content)) return;
            var dto = new IceCandidateDto(cand.Mid, 0, cand.Content);
            _localIce.Enqueue(dto);
            LocalIce?.Invoke(dto);
        };
        _pc.OnGatheringStateChange += (_, state) =>
        {
            if (state == rtcGatheringState.RTC_GATHERING_COMPLETE)
                _iceGatherDone.TrySetResult(true);
        };
        _pc.OnConnectionStateChange += (_, state) =>
        {
            if (_disposed) return;
            if (state == rtcState.RTC_FAILED)
                _error = "ICE connection failed";
        };
        _pc.OnIceStateChange += (_, state) =>
        {
            if (_disposed) return;
            if (state == rtcIceState.RTC_ICE_FAILED)
                _error = "ICE connection failed";
        };
        _pc.OnDataChannel += (_, dc) => AttachDataChannel(dc);

        if (isHost)
        {
            // Auto-negotiation: this also sets the local offer and starts gathering.
            var dc = _pc.CreateDataChannel(new RtcCreateDataChannelArgs
            {
                Label = DcLabel,
                Protocol = RtcDataChannelProtocol.Binary
            });
            AttachDataChannel(dc);
        }
    }

    public string? Error => _error;
    public bool IsDataChannelOpen => _dcOpen.Task.IsCompletedSuccessfully && _dcOpen.Task.Result;

    /// <summary>Max TYPE_CHUNK payload for the current peer.</summary>
    public int MaxPayloadBytes() =>
        DcChunkLimits.WirePayloadBytes(_remoteMaxMessageSize, DcChunkLimits.LocalMaxMessageSize);

    public async Task<string> CreateOfferSdpAsync(CancellationToken ct = default)
    {
        // The offer was auto-created when the DataChannel was opened in the ctor.
        // Android libwebrtc needs candidates embedded in the SDP body, so wait
        // for gathering before returning it.
        await WaitGatheringAsync(ct).ConfigureAwait(false);
        return CurrentLocalSdp();
    }

    public async Task<string> ApplyRemoteOfferAndCreateAnswerAsync(string remoteSdp, CancellationToken ct = default)
    {
        NoteRemoteMaxMessageSize(remoteSdp);
        _pc.SetRemoteDescription(new RtcDescription { Sdp = remoteSdp, Type = RtcDescriptionType.Offer });
        MarkRemoteSet();
        // Auto-negotiation creates the answer; wait for gathering to embed candidates.
        await WaitGatheringAsync(ct).ConfigureAwait(false);
        return CurrentLocalSdp();
    }

    public Task ApplyRemoteAnswerAsync(string remoteSdp)
    {
        NoteRemoteMaxMessageSize(remoteSdp);
        _pc.SetRemoteDescription(new RtcDescription { Sdp = remoteSdp, Type = RtcDescriptionType.Answer });
        MarkRemoteSet();
        return Task.CompletedTask;
    }

    public void AddRemoteIce(string? sdpMid, int sdpMLineIndex, string candidate)
    {
        if (_disposed || string.IsNullOrWhiteSpace(candidate)) return;
        var dto = new IceCandidateDto(sdpMid, sdpMLineIndex, candidate);
        lock (_pendingRemoteIce)
        {
            if (!_remoteDescSet)
            {
                _pendingRemoteIce.Add(dto);
                return;
            }
        }
        AddRemoteIceNow(dto);
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
        var dc = _dc;
        if (_disposed || dc is null || !dc.IsOpen) return false;
        try
        {
            dc.Send((ReadOnlySpan<byte>)bytes);
            Interlocked.Add(ref _bytesSincePause, bytes.LongLength);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Wait until the DataChannel send queue is at/under [threshold]. libdatachannel
    /// buffers unboundedly in user space, so without this a large file would be
    /// swallowed into memory instantly and progress/speed would be fiction.
    /// </summary>
    public async Task<bool> AwaitSendBufferLowAsync(
        long threshold = DcChunkLimits.SendHighWaterBytes,
        TimeSpan? timeout = null,
        CancellationToken ct = default)
    {
        if (_dc is null || !_dc.IsOpen) return false;
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(90));

        while (DateTime.UtcNow < deadline)
        {
            ct.ThrowIfCancellationRequested();
            var dc = _dc;
            if (_disposed || dc is null || !dc.IsOpen) return false;

            var buffered = BufferedAmount();
            if (buffered >= 0)
            {
                if (buffered <= threshold)
                {
                    Interlocked.Exchange(ref _bytesSincePause, 0);
                    return true;
                }
                await Task.Delay(2, ct).ConfigureAwait(false);
                continue;
            }

            // Native bufferedAmount unavailable (binding layout changed) — soft-pace.
            var sent = Interlocked.Read(ref _bytesSincePause);
            var softCap = Math.Min(threshold, DcChunkLimits.SoftHighWaterBytes);
            if (sent < softCap) return true;
            var sleepMs = (int)Math.Clamp(
                (sent * 1000L) / Math.Max(1L, DcChunkLimits.SoftPaceBytesPerSec),
                8,
                400);
            Interlocked.Exchange(ref _bytesSincePause, 0);
            await Task.Delay(sleepMs, ct).ConfigureAwait(false);
            return _dc?.IsOpen == true;
        }

        return false;
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

    private void AttachDataChannel(IRtcDataChannel dc)
    {
        _dc = dc;
        if (dc is RtcDataChannel impl && ChannelIdField?.GetValue(impl) is int id)
            _dcChannelId = id;
        dc.OnOpen += _ => _dcOpen.TrySetResult(true);
        dc.OnError += (_, err) =>
        {
            if (!_disposed) _error ??= string.IsNullOrWhiteSpace(err) ? "DataChannel error" : err;
        };
        dc.OnBinaryReceivedSafe += (_, e) =>
        {
            if (_disposed) return;
            var copy = e.Data.ToArray();
            _incoming.Enqueue(copy);
            _incomingSignal.Release();
            MessageReceived?.Invoke(copy);
        };
        if (dc.IsOpen)
            _dcOpen.TrySetResult(true);
    }

    private long BufferedAmount()
    {
        var id = _dcChannelId;
        if (id < 0) return -1;
        try
        {
            var n = Rtc.rtcGetBufferedAmount(id);
            return n < 0 ? -1 : n;
        }
        catch
        {
            return -1;
        }
    }

    private void NoteRemoteMaxMessageSize(string sdp)
    {
        _remoteMaxMessageSize = WebRtcSdpCompat.ParseMaxMessageSize(sdp)
            ?? DcChunkLimits.DefaultMaxMessageSize;
    }

    private void AddRemoteIceNow(IceCandidateDto dto)
    {
        try
        {
            _pc.AddRemoteCandidate(new RtcCandidate
            {
                Content = dto.Sdp,
                Mid = string.IsNullOrWhiteSpace(dto.SdpMid) ? "0" : dto.SdpMid
            });
        }
        catch
        {
            // Malformed/late candidates are non-fatal; other pairs still connect.
        }
    }

    private void MarkRemoteSet()
    {
        List<IceCandidateDto> pending;
        lock (_pendingRemoteIce)
        {
            _remoteDescSet = true;
            pending = _pendingRemoteIce.ToList();
            _pendingRemoteIce.Clear();
        }
        foreach (var c in pending)
            AddRemoteIceNow(c);
    }

    private string CurrentLocalSdp()
    {
        var sdp = _pc.LocalDescription;
        if (string.IsNullOrWhiteSpace(sdp))
            throw new InvalidOperationException("Empty local SDP");
        // libdatachannel embeds gathered candidates itself; the compat pass dedups,
        // ensures max-message-size, and rewrites ice-options for Android libwebrtc.
        sdp = WebRtcSdpCompat.WithMaxMessageSize(sdp, DcChunkLimits.LocalMaxMessageSize);
        return WebRtcSdpCompat.WithEmbeddedCandidates(sdp, _localIce.ToArray());
    }

    private async Task WaitGatheringAsync(CancellationToken ct)
    {
        try
        {
            // 4s cap — gathering normally completes in well under a second.
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linked.CancelAfter(TimeSpan.FromSeconds(4));
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
        try { _pc.Dispose(); } catch { /* ignore */ }
        _dc = null;
        _dcChannelId = -1;
        _dcOpen.TrySetResult(false);
        _iceGatherDone.TrySetResult(true);
        _incomingSignal.Release();
    }
}
