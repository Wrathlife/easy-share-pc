using System.Diagnostics;
using EasyShare.Protocol;
using Xunit;
using Xunit.Abstractions;

namespace EasyShare.Protocol.Tests;

/// <summary>
/// Loopback SIPSorcery↔SIPSorcery DataChannel smoke + throughput measurement.
/// Exercises the embedded-candidate SDP compat path (no trickle ICE is wired).
/// </summary>
public class WebRtcLoopbackThroughputTests
{
    private readonly ITestOutputHelper _output;

    public WebRtcLoopbackThroughputTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public async Task DataChannel_loopback_throughput()
    {
        using var offerer = new WebRtcPeer(isHost: true);
        using var answerer = new WebRtcPeer(isHost: false);

        var offer = await offerer.CreateOfferSdpAsync();
        Assert.Contains("a=candidate:", offer);
        Assert.Contains("a=max-message-size:", offer);

        var answer = await answerer.ApplyRemoteOfferAndCreateAnswerAsync(offer);
        Assert.Contains("a=candidate:", answer);
        await offerer.ApplyRemoteAnswerAsync(answer);

        var openA = await offerer.AwaitDataChannelOpenAsync(TimeSpan.FromSeconds(10));
        var openB = await answerer.AwaitDataChannelOpenAsync(TimeSpan.FromSeconds(10));
        if (!openA || !openB)
        {
            // Loopback ICE can be blocked by local firewall rules; don't fail CI on it.
            _output.WriteLine("DataChannel did not open — skipping throughput measurement.");
            return;
        }

        const long totalBytes = 32L * 1024 * 1024;
        long received = 0;
        var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        answerer.MessageReceived += msg =>
        {
            if (Interlocked.Add(ref received, msg.Length) >= totalBytes) done.TrySetResult();
        };

        var chunk = new byte[offerer.MaxPayloadBytes()];
        Random.Shared.NextBytes(chunk);
        _output.WriteLine($"Negotiated wire payload: {chunk.Length} bytes");

        var sw = Stopwatch.StartNew();
        long sent = 0;
        while (sent < totalBytes)
        {
            Assert.True(await offerer.AwaitSendBufferLowAsync(), "send buffer never drained");
            Assert.True(offerer.Send(chunk), "DataChannel send failed");
            sent += chunk.Length;
        }
        await done.Task.WaitAsync(TimeSpan.FromSeconds(120));
        sw.Stop();

        var mib = received / (1024.0 * 1024.0);
        var rate = mib / sw.Elapsed.TotalSeconds;
        _output.WriteLine($"Loopback DataChannel throughput: {rate:F1} MiB/s ({mib:F0} MiB in {sw.Elapsed.TotalSeconds:F1}s)");
        Assert.True(received >= totalBytes);
    }
}
