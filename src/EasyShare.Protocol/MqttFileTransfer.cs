using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace EasyShare.Protocol;

/// <summary>Chunked MQTT AES file transfer — parity with Android MqttEncryptedFileTransfer.</summary>
public sealed class MqttFileTransfer
{
    private readonly Func<string, int, Task> _publishSealed;
    private readonly Func<byte[]> _authKey;
    private readonly Func<long> _sessionExp;
    private readonly Func<bool> _isLive;
    private readonly Action<TransferProgress?> _progress;
    private readonly Action<IReadOnlyList<SavedFileRecord>> _saved;
    private readonly Action _complete;
    private readonly Action<string> _failed;

    private string? _receiveRoot;
    private FileStream? _currentOut;
    private string? _currentPartial;
    private string? _currentFinal;
    private string? _currentPath;
    private long _currentExpected = -1;
    private long _currentWritten;
    private int _currentSeq;
    private readonly MqttChunkAssembler _assembler = new();
    private bool _pendingFdone;
    private readonly object _receiveLock = new();
    private readonly List<SavedFileRecord> _pendingSaved = new();
    private long _receiveTotalBytes;
    private long _receiveDoneBytes;
    private bool _receiveStarted;
    private volatile bool _peerAcked;
    private long _speedWindowStartMs;
    private long _speedWindowBytes;
    private long _lastMeasuredSpeed;
    private CancellationTokenSource? _sendCts;

    public MqttFileTransfer(
        Func<string, int, Task> publishSealed,
        Func<byte[]> authKey,
        Func<long> sessionExp,
        Func<bool> isLive,
        Action<TransferProgress?> progress,
        Action<IReadOnlyList<SavedFileRecord>> saved,
        Action complete,
        Action<string> failed)
    {
        _publishSealed = publishSealed;
        _authKey = authKey;
        _sessionExp = sessionExp;
        _isLive = isLive;
        _progress = progress;
        _saved = saved;
        _complete = complete;
        _failed = failed;
    }

    public void MarkPeerAcked() => _peerAcked = true;

    public void Reset()
    {
        _sendCts?.Cancel();
        _sendCts = null;
        lock (_receiveLock)
        {
            DiscardIncompleteReceive();
            _receiveRoot = null;
            _receiveStarted = false;
            _peerAcked = false;
            _pendingSaved.Clear();
            _receiveTotalBytes = 0;
            _receiveDoneBytes = 0;
            ResetSpeedWindow();
            _progress(null);
            _saved(Array.Empty<SavedFileRecord>());
        }
    }

    public void Abort(string reason)
    {
        Reset();
        _failed(reason);
    }

    public void PrepareGuestSink(string receiveRoot, IReadOnlyList<SharedFileInfo> expected)
    {
        if (_receiveRoot is null)
        {
            Directory.CreateDirectory(receiveRoot);
            _receiveRoot = receiveRoot;
            foreach (var f in Directory.EnumerateFiles(receiveRoot, "*.partial"))
                File.Delete(f);
            // #region agent log
            AgentDebug.Log("wipe-folder", "MqttFileTransfer.cs:PrepareGuestSink", "prepared session sink without recursive delete",
                new { receiveRoot }, "post-fix");
            // #endregion
        }
        if (_receiveStarted) return;
        if (expected.Count > 0)
        {
            _receiveTotalBytes = Math.Max(1, expected.Sum(e => Math.Max(1, e.SizeBytes)));
            _progress(new TransferProgress(
                false, 0, _receiveTotalBytes, expected[0].Name, 0,
                Math.Max(1, expected[0].SizeBytes), 0, null));
        }
    }

    public async Task StartHostSendAsync(IReadOnlyList<LocalShareEntry> entries, CancellationToken ct = default)
    {
        _sendCts?.Cancel();
        _sendCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var token = _sendCts.Token;
        _peerAcked = false;
        try
        {
            await Task.Delay(400, token).ConfigureAwait(false);
            var total = Math.Max(1, entries.Sum(e => Math.Max(1, e.SizeBytes)));
            long overallDone = 0;
            ResetSpeedWindow();
            for (var index = 0; index < entries.Count; index++)
            {
                token.ThrowIfCancellationRequested();
                if (!_isLive()) return;
                var entry = entries[index];
                if (entry.SizeBytes > ProtocolPaths.MaxFileBytes)
                {
                    Fail($"“{entry.DisplayName}” is too large");
                    return;
                }
                await PublishFileEventAsync("fstart", entry.RelativePath, Math.Max(0, entry.SizeBytes), 0, "", "", 1, token)
                    .ConfigureAwait(false);
                var fileTotal = Math.Max(1, entry.SizeBytes);
                long fileDone = 0;
                var chunkBytes = PreferredChunkBytes(entry.SizeBytes);
                await using var input = File.OpenRead(entry.AbsolutePath);
                var buf = new byte[chunkBytes];
                var seq = 0;
                while (true)
                {
                    token.ThrowIfCancellationRequested();
                    if (!_isLive()) return;
                    var n = await input.ReadAsync(buf.AsMemory(0, buf.Length), token).ConfigureAwait(false);
                    if (n <= 0) break;
                    var chunk = n == buf.Length ? buf.ToArray() : buf.AsSpan(0, n).ToArray();
                    var digest = ProtocolPaths.Sha256Hex(chunk);
                    var b64 = Convert.ToBase64String(chunk);
                    await PublishFileEventAsync("fbin", entry.RelativePath, entry.SizeBytes, seq, digest, b64, 1, token)
                        .ConfigureAwait(false);
                    seq++;
                    fileDone += n;
                    overallDone += n;
                    var speed = NoteBytes(n);
                    var remain = Math.Max(0, total - overallDone);
                    long? eta = remain == 0
                        ? null
                        : speed > 0 ? Math.Max(1, remain / speed) : null;
                    _progress(new TransferProgress(true, Math.Min(overallDone, total), total,
                        entry.RelativePath, Math.Min(fileDone, fileTotal), fileTotal, speed, eta));
                    await Task.Yield();
                }
                await PublishFileEventAsync("fdone", entry.RelativePath, entry.SizeBytes, 0, "", "", 1, token)
                    .ConfigureAwait(false);
            }
            await PublishSignedSimpleAsync("h", "xfer-complete", token).ConfigureAwait(false);
            var ackDeadline = DateTime.UtcNow.AddSeconds(20);
            while (DateTime.UtcNow < ackDeadline && !_peerAcked && !token.IsCancellationRequested)
                await Task.Delay(100, token).ConfigureAwait(false);
            if (!_peerAcked)
            {
                // #region agent log
                AgentDebug.Log("false-success", "MqttFileTransfer.cs:StartHostSendAsync", "mqtt host missing xfer-ack",
                    new { }, "post-fix");
                // #endregion
                Fail("Receiver did not confirm the transfer");
                return;
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

    public void OnGuestEvent(string eventName, JsonObject obj)
    {
        lock (_receiveLock)
        {
            switch (eventName)
            {
                case "fstart":
                {
                    var path = ProtocolPaths.SanitizeWirePath(obj["path"]?.GetValue<string>() ?? "");
                    if (path is null) return;
                    if (_receiveRoot is null)
                    {
                        Fail("Receiver wasn’t ready when transfer started — ask sharer to send again");
                        return;
                    }
                    var size = obj["size"]?.GetValue<long>() ?? -1L;
                    if (size < 0 || size > ProtocolPaths.MaxFileBytes)
                    {
                        Fail("File size is missing or too large");
                        return;
                    }
                    DiscardIncompleteReceive();
                    var bound = ProtocolPaths.BindUnderRoot(_receiveRoot, path);
                    if (bound is null)
                    {
                        Fail("Invalid file path");
                        return;
                    }
                    var partial = bound + ".partial";
                    if (File.Exists(partial)) File.Delete(partial);
                    if (File.Exists(bound)) File.Delete(bound);
                    Directory.CreateDirectory(Path.GetDirectoryName(partial)!);
                    _currentOut = new FileStream(partial, FileMode.Create, FileAccess.Write, FileShare.None);
                    _currentPartial = partial;
                    _currentFinal = bound;
                    _currentPath = path;
                    _currentExpected = size;
                    _currentWritten = 0;
                    _currentSeq = 0;
                    _assembler.Reset();
                    _pendingFdone = false;
                    _receiveStarted = true;
                    ResetSpeedWindow();
                    if (_receiveTotalBytes <= 0 && size > 0) _receiveTotalBytes = Math.Max(1, size);
                    break;
                }
                case "fbin":
                {
                    var path = ProtocolPaths.SanitizeWirePath(obj["path"]?.GetValue<string>() ?? "");
                    if (path is null || path != _currentPath) return;
                    var seq = obj["seq"]?.GetValue<int>() ?? -1;
                    var digest = obj["digest"]?.GetValue<string>() ?? "";
                    var b64 = obj["d"]?.GetValue<string>() ?? "";
                    if (b64.Length > PreferredChunkBytes(ProtocolPaths.MaxFileBytes) * 2)
                    {
                        Fail($"Chunk too large for {path}");
                        return;
                    }
                    byte[] bytes;
                    try { bytes = Convert.FromBase64String(b64); }
                    catch { return; }
                    if (bytes.Length > 48 * 1024)
                    {
                        Fail($"Chunk too large for {path}");
                        return;
                    }
                    if (ProtocolPaths.Sha256Hex(bytes) != digest)
                    {
                        Fail($"Chunk integrity failed for {path}");
                        return;
                    }
                    var ready = _assembler.Offer(seq, bytes);
                    if (ready is null)
                    {
                        Fail($"Transfer desync on {path}");
                        return;
                    }
                    if (ready.Count == 0)
                    {
                        if (_pendingFdone) TryFinalizeCurrent(path);
                        return;
                    }
                    long added = 0;
                    foreach (var chunk in ready)
                    {
                        if (_currentExpected >= 0 && _currentWritten + chunk.Length > _currentExpected)
                        {
                            Fail($"Size overflow for {path}");
                            return;
                        }
                        _currentOut?.Write(chunk);
                        _currentWritten += chunk.Length;
                        _currentSeq++;
                        _receiveDoneBytes += chunk.Length;
                        added += chunk.Length;
                    }
                    var speed = NoteBytes(added);
                    var remain = Math.Max(0, _receiveTotalBytes - _receiveDoneBytes);
                    long? eta = speed > 0 ? Math.Max(1, remain / speed) : null;
                    _progress(new TransferProgress(false, Math.Min(_receiveDoneBytes, _receiveTotalBytes),
                        _receiveTotalBytes, path, _currentWritten, Math.Max(1, _currentExpected), speed, eta));
                    if (_pendingFdone) TryFinalizeCurrent(path);
                    break;
                }
                case "fdone":
                {
                    var path = ProtocolPaths.SanitizeWirePath(obj["path"]?.GetValue<string>() ?? "");
                    if (path is null || path != _currentPath) return;
                    _pendingFdone = true;
                    TryFinalizeCurrent(path);
                    break;
                }
                case "xfer-complete":
                    DiscardIncompleteReceive();
                    _saved(_pendingSaved.ToList());
                    _ = PublishSignedSimpleAsync("g", "xfer-ack", CancellationToken.None);
                    _complete();
                    break;
            }
        }
    }

    public static string TransferExtra(JsonObject obj)
    {
        var path = obj["path"]?.GetValue<string>() ?? "";
        var size = obj["size"]?.GetValue<long>() ?? 0L;
        var seq = obj["seq"]?.GetValue<int>() ?? 0;
        var digest = obj["digest"]?.GetValue<string>() ?? "";
        return string.Join("|", path, size.ToString(), seq.ToString(), digest);
    }

    public static int PreferredChunkBytes(long fileSize)
    {
        const int Kib = 1024;
        const int ChunkBytes = 32 * Kib;
        var size = Math.Max(0, fileSize);
        return size <= ChunkBytes ? Math.Max(1, (int)size) : ChunkBytes;
    }

    private async Task PublishFileEventAsync(
        string eventName, string path, long size, int seq, string digest, string dataB64, int qos, CancellationToken ct)
    {
        var key = _authKey();
        if (key.Length == 0) return;
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var exp = _sessionExp();
        var nonce = SignalingCrypto.RandomNonce();
        var extra = string.Join("|", path, size.ToString(), seq.ToString(), digest);
        var mac = SignalingCrypto.MacHex(key, SignalingCrypto.Canonical("h", eventName, ts, exp, nonce, extra));
        var inner = new JsonObject
        {
            ["r"] = "h",
            ["e"] = eventName,
            ["ts"] = ts,
            ["exp"] = exp,
            ["nonce"] = nonce,
            ["mac"] = mac,
            ["path"] = path,
            ["size"] = size,
            ["seq"] = seq,
            ["digest"] = digest,
            ["d"] = dataB64
        }.ToJsonString(new JsonSerializerOptions { WriteIndented = false });
        await _publishSealed(inner, qos).ConfigureAwait(false);
    }

    private async Task PublishSignedSimpleAsync(string roleChar, string eventName, CancellationToken ct)
    {
        var key = _authKey();
        if (key.Length == 0) return;
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var exp = _sessionExp();
        var nonce = SignalingCrypto.RandomNonce();
        var mac = SignalingCrypto.MacHex(key, SignalingCrypto.Canonical(roleChar, eventName, ts, exp, nonce));
        var inner = new JsonObject
        {
            ["r"] = roleChar,
            ["e"] = eventName,
            ["ts"] = ts,
            ["exp"] = exp,
            ["nonce"] = nonce,
            ["mac"] = mac
        }.ToJsonString();
        await _publishSealed(inner, 1).ConfigureAwait(false);
    }

    private void TryFinalizeCurrent(string path)
    {
        if (_assembler.PendingCount > 0) return;
        if (_currentExpected >= 0 && _currentWritten < _currentExpected) return;
        var partial = _currentPartial;
        var finalFile = _currentFinal;
        try { _currentOut?.Flush(); } catch { /* ignore */ }
        try { _currentOut?.Dispose(); } catch { /* ignore */ }
        _currentOut = null;
        _currentPartial = null;
        _currentFinal = null;
        _currentPath = null;
        _pendingFdone = false;
        _assembler.Reset();
        if (partial is null || finalFile is null || !File.Exists(partial))
        {
            Fail($"Incomplete file on disk for {path}");
            return;
        }
        var len = new FileInfo(partial).Length;
        if (_currentExpected < 0 || len != _currentExpected)
        {
            File.Delete(partial);
            Fail($"Size mismatch for {path}");
            return;
        }
        if (File.Exists(finalFile)) File.Delete(finalFile);
        File.Move(partial, finalFile);
        _pendingSaved.Add(new SavedFileRecord(path, new FileInfo(finalFile).Length, finalFile));
        _saved(_pendingSaved.ToList());
    }

    private void DiscardIncompleteReceive()
    {
        try { _currentOut?.Dispose(); } catch { /* ignore */ }
        _currentOut = null;
        if (_currentPartial is not null && File.Exists(_currentPartial))
            try { File.Delete(_currentPartial); } catch { /* ignore */ }
        _currentPartial = null;
        _currentFinal = null;
        _currentPath = null;
        _pendingFdone = false;
        _assembler.Reset();
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
        else if (_lastMeasuredSpeed == 0 && elapsed >= 250)
        {
            _lastMeasuredSpeed = (_speedWindowBytes * 1000L) / elapsed;
        }
        return _lastMeasuredSpeed;
    }

    private void Fail(string reason)
    {
        DiscardIncompleteReceive();
        _failed(reason);
    }
}
