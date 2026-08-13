using System.Buffers.Binary;
using System.Text;

namespace EasyShare.Protocol;

/// <summary>Binary DataChannel framing — parity with Android DataChannelFileTransfer.</summary>
public static class DcFrames
{
    public const byte TypeHello = 1;
    public const byte TypeFileBegin = 2;
    public const byte TypeReady = 3;
    public const byte TypeChunk = 5;
    public const byte TypeFileDone = 8;
    public const byte TypeXferDone = 9;
    public const byte TypeXferAck = 10;
    public const int ChunkBytes = 64 * 1024;

    public static byte[] Frame(byte type, ReadOnlySpan<byte> payload)
    {
        var outBuf = new byte[5 + payload.Length];
        outBuf[0] = type;
        BinaryPrimitives.WriteInt32BigEndian(outBuf.AsSpan(1, 4), payload.Length);
        payload.CopyTo(outBuf.AsSpan(5));
        return outBuf;
    }

    public static byte[] EncodeHello() => Frame(TypeHello, new byte[] { 1 });
    public static byte[] EncodeReady() => Frame(TypeReady, ReadOnlySpan<byte>.Empty);
    public static byte[] EncodeXferAck() => Frame(TypeXferAck, ReadOnlySpan<byte>.Empty);
    public static byte[] EncodeXferDone() => Frame(TypeXferDone, ReadOnlySpan<byte>.Empty);

    public static byte[] EncodeFileBegin(int index, string path, long size)
    {
        var pathBytes = Encoding.UTF8.GetBytes(path);
        var payload = new byte[4 + 2 + pathBytes.Length + 8];
        BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(0, 4), index);
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(4, 2), (ushort)pathBytes.Length);
        pathBytes.CopyTo(payload.AsSpan(6));
        BinaryPrimitives.WriteInt64BigEndian(payload.AsSpan(6 + pathBytes.Length, 8), size);
        return Frame(TypeFileBegin, payload);
    }

    public static byte[] EncodeChunk(int index, long offset, ReadOnlySpan<byte> data)
    {
        var payload = new byte[4 + 8 + data.Length];
        BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(0, 4), index);
        BinaryPrimitives.WriteInt64BigEndian(payload.AsSpan(4, 8), offset);
        data.CopyTo(payload.AsSpan(12));
        return Frame(TypeChunk, payload);
    }

    public static byte[] EncodeFileDone(int index, string path, long size)
    {
        var pathBytes = Encoding.UTF8.GetBytes(path);
        var payload = new byte[4 + 2 + pathBytes.Length + 8];
        BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(0, 4), index);
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(4, 2), (ushort)pathBytes.Length);
        pathBytes.CopyTo(payload.AsSpan(6));
        BinaryPrimitives.WriteInt64BigEndian(payload.AsSpan(6 + pathBytes.Length, 8), size);
        return Frame(TypeFileDone, payload);
    }

    public static bool TryParse(ReadOnlySpan<byte> frame, out byte type, out ReadOnlySpan<byte> payload)
    {
        type = 0;
        payload = default;
        if (frame.Length < 5) return false;
        type = frame[0];
        var len = BinaryPrimitives.ReadInt32BigEndian(frame.Slice(1, 4));
        if (len < 0 || 5 + len > frame.Length) return false;
        payload = frame.Slice(5, len);
        return true;
    }
}
