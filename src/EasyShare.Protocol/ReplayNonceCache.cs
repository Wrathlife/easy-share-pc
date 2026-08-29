namespace EasyShare.Protocol;

/// <summary>Bounded unique-nonce memory for MQTT replay protection.</summary>
public sealed class ReplayNonceCache
{
    public const int MaxSeen = 65_536;

    private readonly object _gate = new();
    private readonly HashSet<string> _set = new(StringComparer.Ordinal);
    private readonly Queue<string> _order = new();

    public int Count
    {
        get { lock (_gate) return _set.Count; }
    }

    /// <summary>False = reject (blank or duplicate). True = first time seeing this nonce.</summary>
    public bool TryRemember(string nonce)
    {
        if (string.IsNullOrWhiteSpace(nonce))
        {
            return false;
        }
        lock (_gate)
        {
            if (!_set.Add(nonce)) return false;
            _order.Enqueue(nonce);
            while (_set.Count > MaxSeen)
            {
                var old = _order.Dequeue();
                _set.Remove(old);
            }
            return true;
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _set.Clear();
            _order.Clear();
        }
    }
}
