using EasyShare.Protocol;
using Xunit;

namespace EasyShare.Protocol.Tests;

public class MqttChunkAssemblerTests
{
    [Fact]
    public void InOrderChunksFlushImmediately()
    {
        var a = new MqttChunkAssembler();
        var first = a.Offer(0, new byte[] { 1 })!;
        Assert.Single(first);
        Assert.Equal(new byte[] { 1 }, first[0]);
        var second = a.Offer(1, new byte[] { 2 })!;
        Assert.Single(second);
        Assert.Equal(new byte[] { 2 }, second[0]);
    }

    [Fact]
    public void OutOfOrderBuffersThenDrains()
    {
        var a = new MqttChunkAssembler();
        Assert.Empty(a.Offer(2, new byte[] { 2 })!);
        Assert.Empty(a.Offer(1, new byte[] { 1 })!);
        Assert.Equal(2, a.PendingCount);
        var ready = a.Offer(0, new byte[] { 0 })!;
        Assert.Equal(3, ready.Count);
        Assert.Equal(new byte[] { 0 }, ready[0]);
        Assert.Equal(new byte[] { 1 }, ready[1]);
        Assert.Equal(new byte[] { 2 }, ready[2]);
        Assert.Equal(0, a.PendingCount);
    }

    [Fact]
    public void DuplicatesAreIgnored()
    {
        var a = new MqttChunkAssembler();
        a.Offer(0, new byte[] { 1 });
        Assert.Empty(a.Offer(0, new byte[] { 9 })!);
        var next = a.Offer(1, new byte[] { 2 })!;
        Assert.Single(next);
        Assert.Equal(new byte[] { 2 }, next[0]);
    }

    [Fact]
    public void OverflowFailsInsteadOfDesyncGuess()
    {
        var a = new MqttChunkAssembler(maxBuffered: 2);
        Assert.Empty(a.Offer(1, new byte[] { 1 })!);
        Assert.Empty(a.Offer(2, new byte[] { 2 })!);
        Assert.Null(a.Offer(3, new byte[] { 3 }));
    }

    [Fact]
    public void PreferredChunkStaysSmallForLargeFiles()
    {
        const int kib = 1024;
        Assert.Equal(1, MqttFileTransfer.PreferredChunkBytes(0));
        Assert.Equal(16 * kib, MqttFileTransfer.PreferredChunkBytes(16L * kib));
        Assert.Equal(32 * kib, MqttFileTransfer.PreferredChunkBytes(32L * kib));
        Assert.Equal(32 * kib, MqttFileTransfer.PreferredChunkBytes(400L * 1024 * kib));
        Assert.Equal(10 * kib, MqttFileTransfer.PreferredChunkBytes(10L * kib));
    }
}

public class ReplayNonceCacheTests
{
    [Fact]
    public void RejectsBlankAndDuplicates()
    {
        var cache = new ReplayNonceCache();
        Assert.False(cache.TryRemember(""));
        Assert.False(cache.TryRemember("   "));
        Assert.True(cache.TryRemember("n1"));
        Assert.False(cache.TryRemember("n1"));
        Assert.True(cache.TryRemember("n2"));
        Assert.Equal(2, cache.Count);
        cache.Clear();
        Assert.Equal(0, cache.Count);
        Assert.True(cache.TryRemember("n1"));
    }

    [Fact]
    public void EvictsOldestAfterCap()
    {
        var cache = new ReplayNonceCache();
        for (var i = 0; i < ReplayNonceCache.MaxSeen; i++)
            Assert.True(cache.TryRemember("n" + i));
        Assert.Equal(ReplayNonceCache.MaxSeen, cache.Count);
        Assert.True(cache.TryRemember("overflow"));
        Assert.Equal(ReplayNonceCache.MaxSeen, cache.Count);
        Assert.True(cache.TryRemember("n0"));
    }
}
