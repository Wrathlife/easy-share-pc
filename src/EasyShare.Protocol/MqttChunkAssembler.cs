namespace EasyShare.Protocol;

/// <summary>
/// MQTT 3.1.1 does not guarantee in-order delivery (especially mixed QoS / thread-pool callbacks).
/// Buffer future seqs, ignore duplicates, fail only when the gap window overflows.
/// </summary>
public sealed class MqttChunkAssembler
{
    public const int MaxBuffered = 64;

    private readonly int _maxBuffered;
    private int _nextSeq;
    private readonly SortedDictionary<int, byte[]> _buffered = new();

    public MqttChunkAssembler(int maxBuffered = MaxBuffered)
    {
        _maxBuffered = maxBuffered;
    }

    public int PendingCount => _buffered.Count;

    public void Reset()
    {
        _nextSeq = 0;
        _buffered.Clear();
    }

    /// <summary>
    /// In-order payloads to write, or null if this offer should fail (gap overflow).
    /// Duplicate / not-yet-expected seq returns an empty list.
    /// </summary>
    public List<byte[]>? Offer(int seq, byte[] payload)
    {
        if (seq < 0) return new List<byte[]>();
        if (seq < _nextSeq) return new List<byte[]>();
        if (seq > _nextSeq)
        {
            if (!_buffered.ContainsKey(seq) && _buffered.Count >= _maxBuffered) return null;
            _buffered.TryAdd(seq, payload);
            return new List<byte[]>();
        }
        var ready = new List<byte[]> { payload };
        _nextSeq++;
        while (_buffered.Remove(_nextSeq, out var next))
        {
            ready.Add(next);
            _nextSeq++;
        }
        return ready;
    }
}
