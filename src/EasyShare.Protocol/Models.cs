namespace EasyShare.Protocol;

public sealed record SharedFileInfo(string Name, long SizeBytes);

public sealed record LocalShareEntry(string AbsolutePath, string RelativePath, long SizeBytes)
{
    public string DisplayName => RelativePath;
}

public sealed record SavedFileRecord(string Name, long SizeBytes, string LocalPath);

public sealed record TransferProgress(
    bool Sending,
    long BytesDone,
    long BytesTotal,
    string? CurrentFileName,
    long CurrentFileDone,
    long CurrentFileTotal,
    long SpeedBytesPerSec,
    long? EtaSeconds);

public abstract record PairingState
{
    public sealed record Idle : PairingState;
    public sealed record Connecting : PairingState;
    public sealed record Waiting : PairingState;
    public sealed record Confirming(string Phrase, bool LocalConfirmed, bool PeerConfirmed) : PairingState;
    public sealed record Paired : PairingState;
    public sealed record Failed(string Reason) : PairingState;
}

public sealed record IceCandidateDto(string? SdpMid, int SdpMLineIndex, string Sdp);
