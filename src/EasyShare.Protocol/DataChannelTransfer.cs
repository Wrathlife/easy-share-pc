using System.Buffers.Binary;
using System.Text;

namespace EasyShare.Protocol;

/// <summary>File transfer over an open WebRTC DataChannel.</summary>
public sealed class DataChannelTransfer
{
    private readonly WebRtcPeer _session;
    private readonly Action<TransferProgress?> _progress;
    private readonly Action<IReadOnlyList<SavedFileRecord>> _saved;
    private readonly Action _complete;
    private readonly Action<string> _failed;

    private string? _receiveRoot;
    private FileStream? _currentOut;
    private string? _currentPartial;
    private string? _currentFinal;
    private string? _currentPath;
    private int _currentFileIndex = -1;
    private long _currentExpected = -1;
    private long _currentWritten;
    private readonly List<SavedFileRecord> _pendingSaved = new();
    private int _expectedFileCount;
    private long _receiveTotalBytes;
    private long _receiveDoneBytes;
    private long _speedWindowStartMs;
    private long _speedWindowBytes;
    private long _lastMeasuredSpeed;
    private volatile bool _active;
    private volatile bool _guestReady;
    private volatile bool _guestAcked;
    private CancellationTokenSource? _cts;

    public DataChannelTransfer(
        WebRtcPeer session,
        Action<TransferProgress?> progress,
        Action<IReadOnlyList<SavedFileRecord>> saved,
        Action complete,
        Action<string> failed)
    {
        _session = session;
        _progress = progress;
        _saved = saved;
        _complete = complete;
        _failed = failed;
    }

    public void PrepareGuestSink(string receiveRoot, IReadOnlyList<SharedFileInfo> expected)
    {
        if (_receiveRoot is null)
        {
            if (Directory.Exists(receiveRoot)) Directory.Delete(receiveRoot, true);
            Directory.CreateDirectory(receiveRoot);
            _receiveRoot = receiveRoot;
        }
        if (expected.Count > 0)
        {
            _expectedFileCount = expected.Count;
            _receiveTotalBytes = Math.Max(1, expected.Sum(e => Math.Max(0, e.SizeBytes)));
            _progress(new TransferProgress(false, 0, _receiveTotalBytes, expected[0].Name, 0,
                Math.Max(1, expected[0].SizeBytes), 0, null));
        }
    }

    public async Task StartHostSendAsync(IReadOnlyList<LocalShareEntry> entries, CancellationToken ct = default)
    {
        _cts?.Cancel();
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var token = _cts.Token;
        _active = true;
        _guestReady = false;
        _guestAcked = false;
        _ = Task.Run(async () =>
        {
            await foreach (var frame in _session.IncomingAsync(token))
            {
                if (!_active) break;
                if (frame.Length > 0 && frame[0] == DcFrames.TypeReady) _guestReady = true;
                if (frame.Length > 0 && frame[0] == DcFrames.TypeXferAck) _guestAcked = true;
            }
        }, token);

        try
        {
            if (!await _session.AwaitDataChannelOpenAsync(TimeSpan.FromSeconds(1), token).ConfigureAwait(false))
            {
                Fail("DataChannel not open");
                return;
            }
            var readyDeadline = DateTime.UtcNow.AddSeconds(12);
            while (DateTime.UtcNow < readyDeadline && !_guestReady)
            {
                token.ThrowIfCancellationRequested();
                _session.Send(DcFrames.EncodeHello());
                await Task.Delay(200, token).ConfigureAwait(false);
            }
            if (!_guestReady)
            {
                Fail("Receiver did not become ready");
                return;
            }
            _session.Send(DcFrames.EncodeHello());
            var total = Math.Max(1, entries.Sum(e => Math.Max(1, e.SizeBytes)));
            long overallDone = 0;
            ResetSpeedWindow();
            for (var index = 0; index < entries.Count; index++)
            {
                token.ThrowIfCancellationRequested();
                var entry = entries[index];
                var path = ProtocolPaths.SanitizeWirePath(entry.RelativePath) ?? entry.RelativePath[..Math.Min(180, entry.RelativePath.Length)];
                var declaredSize = Math.Max(0, entry.SizeBytes);
                _session.Send(DcFrames.EncodeFileBegin(index, path, declaredSize));
                await _session.AwaitSendBufferLowAsync(ct: token).ConfigureAwait(false);
                long fileDone = 0;
                var fileTotal = Math.Max(1, declaredSize);
                await using var input = File.OpenRead(entry.AbsolutePath);
                var buf = new byte[DcFrames.ChunkBytes];
                while (true)
                {
                    token.ThrowIfCancellationRequested();
                    var n = await input.ReadAsync(buf.AsMemory(0, buf.Length), token).ConfigureAwait(false);
                    if (n <= 0) break;
                    var chunk = n == buf.Length ? buf : buf.AsSpan(0, n).ToArray();
                    await _session.AwaitSendBufferLowAsync(ct: token).ConfigureAwait(false);
                    if (!_session.Send(DcFrames.EncodeChunk(index, fileDone, chunk)))
                    {
                        Fail("DataChannel send failed");
                        return;
                    }
                    fileDone += n;
                    overallDone += n;
                    var speed = NoteBytes(n);
                    var remain = Math.Max(0, total - overallDone);
                    long? eta = speed > 0 ? Math.Max(1, remain / speed) : null;
                    _progress(new TransferProgress(true, Math.Min(overallDone, total), total,
                        entry.RelativePath, Math.Min(fileDone, fileTotal), fileTotal, speed, eta));
                }
                _session.Send(DcFrames.EncodeFileDone(index, path, fileDone));
            }
            for (var i = 0; i < 3 && !_guestAcked; i++)
            {
                _session.Send(DcFrames.EncodeXferDone());
                await Task.Delay(150, token).ConfigureAwait(false);
            }
            var ackDeadline = DateTime.UtcNow.AddSeconds(20);
            while (DateTime.UtcNow < ackDeadline && !_guestAcked)
            {
                _session.Send(DcFrames.EncodeXferDone());
                await Task.Delay(250, token).ConfigureAwait(false);
            }
            _progress(new TransferProgress(true, total, total, null, 0, 0, _lastMeasuredSpeed, 0));
            _complete();
        }
        catch (OperationCanceledException) { /* stop */ }
        catch (Exception ex)
        {
            Fail(ex.Message);
        }
    }

    public async Task StartGuestReceiveAsync(CancellationToken ct = default)
    {
        _cts?.Cancel();
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var token = _cts.Token;
        _active = true;
        try
        {
            _ = Task.Run(async () =>
            {
                if (await _session.AwaitDataChannelOpenAsync(TimeSpan.FromSeconds(20), token).ConfigureAwait(false))
                    _session.Send(DcFrames.EncodeReady());
            }, token);

            await foreach (var frame in _session.IncomingAsync(token))
            {
                if (!_active) break;
                HandleFrame(frame);
            }
        }
        catch (OperationCanceledException) { /* stop */ }
        catch (Exception ex)
        {
            if (_active) Fail(ex.Message);
        }
    }

    public void Reset()
    {
        _active = false;
        _cts?.Cancel();
        _cts = null;
        DiscardIncomplete();
        _receiveRoot = null;
        _pendingSaved.Clear();
        _expectedFileCount = 0;
        _receiveTotalBytes = 0;
        _receiveDoneBytes = 0;
        ResetSpeedWindow();
    }

    private void HandleFrame(byte[] frame)
    {
        if (!DcFrames.TryParse(frame, out var type, out var payload)) return;
        switch (type)
        {
            case DcFrames.TypeHello:
                _session.Send(DcFrames.EncodeReady());
                break;
            case DcFrames.TypeFileBegin:
            {
                if (payload.Length < 14) return;
                var index = BinaryPrimitives.ReadInt32BigEndian(payload[..4]);
                var pathLen = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(4, 2));
                if (pathLen == 0 || pathLen > 180 || payload.Length < 6 + pathLen + 8) return;
                var path = ProtocolPaths.SanitizeWirePath(Encoding.UTF8.GetString(payload.Slice(6, pathLen)));
                if (path is null || _receiveRoot is null) return;
                var size = BinaryPrimitives.ReadInt64BigEndian(payload.Slice(6 + pathLen, 8));
                DiscardIncomplete();
                var safe = path.Replace('/', '_');
                if (safe.Length > 160) safe = safe[..160];
                var finalFile = Path.Combine(_receiveRoot, safe);
                var partial = finalFile + ".partial";
                if (File.Exists(partial)) File.Delete(partial);
                if (File.Exists(finalFile)) File.Delete(finalFile);
                _currentOut = new FileStream(partial, FileMode.Create, FileAccess.Write, FileShare.None);
                _currentPartial = partial;
                _currentFinal = finalFile;
                _currentPath = path;
                _currentFileIndex = index;
                _currentExpected = size;
                _currentWritten = 0;
                ResetSpeedWindow();
                break;
            }
            case DcFrames.TypeChunk:
            {
                if (payload.Length < 12 || _currentOut is null) return;
                var index = BinaryPrimitives.ReadInt32BigEndian(payload[..4]);
                var offset = BinaryPrimitives.ReadInt64BigEndian(payload.Slice(4, 8));
                if (index != _currentFileIndex || offset != _currentWritten) return;
                var data = payload[12..];
                _currentOut.Write(data);
                _currentWritten += data.Length;
                _receiveDoneBytes += data.Length;
                var speed = NoteBytes(data.Length);
                _progress(new TransferProgress(false, Math.Min(_receiveDoneBytes, _receiveTotalBytes),
                    Math.Max(1, _receiveTotalBytes), _currentPath, _currentWritten,
                    Math.Max(1, _currentExpected), speed,
                    speed > 0 ? Math.Max(1, (_receiveTotalBytes - _receiveDoneBytes) / speed) : null));
                break;
            }
            case DcFrames.TypeFileDone:
            {
                if (payload.Length < 14) return;
                var index = BinaryPrimitives.ReadInt32BigEndian(payload[..4]);
                var pathLen = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(4, 2));
                if (payload.Length < 6 + pathLen + 8) return;
                var path = ProtocolPaths.SanitizeWirePath(Encoding.UTF8.GetString(payload.Slice(6, pathLen)));
                if (path is null || index != _currentFileIndex || path != _currentPath) return;
                var expectedSize = BinaryPrimitives.ReadInt64BigEndian(payload.Slice(6 + pathLen, 8));
                var partial = _currentPartial;
                var finalFile = _currentFinal;
                try { _currentOut?.Flush(); } catch { /* ignore */ }
                try { _currentOut?.Dispose(); } catch { /* ignore */ }
                _currentOut = null;
                _currentPartial = null;
                _currentFinal = null;
                _currentPath = null;
                _currentFileIndex = -1;
                if (partial is null || finalFile is null || !File.Exists(partial))
                {
                    Fail($"Incomplete file on disk for {path}");
                    return;
                }
                var len = new FileInfo(partial).Length;
                if (expectedSize >= 0 && len != expectedSize)
                {
                    File.Delete(partial);
                    Fail($"Size mismatch for {path}");
                    return;
                }
                if (File.Exists(finalFile)) File.Delete(finalFile);
                File.Move(partial, finalFile);
                _pendingSaved.Add(new SavedFileRecord(path, new FileInfo(finalFile).Length, finalFile));
                _saved(_pendingSaved.ToList());
                if (_expectedFileCount > 0 && _pendingSaved.Count >= _expectedFileCount)
                    MarkGuestComplete();
                break;
            }
            case DcFrames.TypeXferDone:
                DiscardIncomplete();
                MarkGuestComplete();
                break;
        }
    }

    private void MarkGuestComplete()
    {
        _session.Send(DcFrames.EncodeXferAck());
        _saved(_pendingSaved.ToList());
        _progress(new TransferProgress(false, Math.Max(1, _receiveTotalBytes), Math.Max(1, _receiveTotalBytes),
            null, 0, 0, _lastMeasuredSpeed, 0));
        _complete();
        _active = false;
    }

    private void DiscardIncomplete()
    {
        try { _currentOut?.Dispose(); } catch { /* ignore */ }
        _currentOut = null;
        if (_currentPartial is not null && File.Exists(_currentPartial))
            try { File.Delete(_currentPartial); } catch { /* ignore */ }
        _currentPartial = null;
        _currentFinal = null;
        _currentPath = null;
        _currentFileIndex = -1;
    }

    private void ResetSpeedWindow()
    {
        _speedWindowStartMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        _speedWindowBytes = 0;
        _lastMeasuredSpeed = 0;
    }

    private long NoteBytes(long n)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        if (_speedWindowStartMs == 0) _speedWindowStartMs = now;
        _speedWindowBytes += n;
        var elapsed = Math.Max(1, now - _speedWindowStartMs);
        if (elapsed >= 750)
        {
            _lastMeasuredSpeed = (_speedWindowBytes * 1000L) / elapsed;
            _speedWindowStartMs = now;
            _speedWindowBytes = 0;
        }
        else if (_lastMeasuredSpeed == 0)
            _lastMeasuredSpeed = (_speedWindowBytes * 1000L) / elapsed;
        return _lastMeasuredSpeed;
    }

    private void Fail(string reason)
    {
        _active = false;
        DiscardIncomplete();
        _failed(reason);
    }
}
