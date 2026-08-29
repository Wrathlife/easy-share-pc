namespace EasyShare.Protocol;

/// <summary>
/// WebRTC DataChannel chunk sizing — parity with Android DcChunkLimits.
/// Preferred chunk is 8 MiB; on-wire payloads are clamped to the negotiated
/// SCTP max-message-size. Windows (libdatachannel) advertises 256 KiB.
/// </summary>
public static class DcChunkLimits
{
    public const int PreferredChunkBytes = 8 * 1024 * 1024;
    public const int FrameOverhead = 32;
    public const int DefaultMaxMessageSize = 256 * 1024;
    /// <summary>Local max-message-size advertised in SDP and set on the peer connection.</summary>
    public const int LocalMaxMessageSize = 256 * 1024;
    public const int AdvertisedMaxMessageSize = PreferredChunkBytes + FrameOverhead;
    /// <summary>When bufferedAmount works — allow this much in the SCTP queue.</summary>
    public const long SendHighWaterBytes = 2L * 1024L * 1024L;
    /// <summary>When bufferedAmount is unavailable — pause after this many enqueued bytes.</summary>
    public const long SoftHighWaterBytes = 512L * 1024L;
    /// <summary>Soft enqueue cap used only when bufferedAmount never moves (avoids fake GB/s).</summary>
    public const long SoftPaceBytesPerSec = 8L * 1024L * 1024L;

    public static int WirePayloadBytes(int remoteMaxMessageSize, int localMaxMessageSize = LocalMaxMessageSize)
    {
        var remote = remoteMaxMessageSize <= 0 ? DefaultMaxMessageSize : remoteMaxMessageSize;
        var local = localMaxMessageSize <= 0 ? LocalMaxMessageSize : localMaxMessageSize;
        var maxMsg = Math.Min(remote, local);
        var payload = maxMsg - FrameOverhead;
        return Math.Clamp(payload, 16 * 1024, PreferredChunkBytes);
    }
}
