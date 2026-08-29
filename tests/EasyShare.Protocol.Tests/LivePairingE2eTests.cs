using System.Diagnostics;
using System.Text;
using EasyShare.Protocol;
using Xunit;
using Xunit.Abstractions;

namespace EasyShare.Protocol.Tests;

/// <summary>
/// Live end-to-end pairing + MQTT file transfer against the real public broker.
/// Runs only when EASYSHARE_LIVE_E2E=1 (network-dependent, not part of the normal suite).
/// Run with: dotnet test --filter LivePairingE2e
/// </summary>
public class LivePairingE2eTests
{
    private readonly ITestOutputHelper _out;

    public LivePairingE2eTests(ITestOutputHelper output) => _out = output;

    private static bool Enabled =>
        Environment.GetEnvironmentVariable("EASYSHARE_LIVE_E2E") == "1";

    [Fact]
    public async Task PairAndTransferOverRealBroker()
    {
        if (!Enabled)
        {
            _out.WriteLine("Skipped — set EASYSHARE_LIVE_E2E=1 to run the live broker test.");
            return;
        }

        var code = PairingCode.GenerateShort();
        _out.WriteLine($"code topic id8: {SignalingCrypto.TopicId(code)[..8]}");

        var tempRoot = Path.Combine(Path.GetTempPath(), "es-e2e-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempRoot);
        var sendPath = Path.Combine(tempRoot, "hello.txt");
        var payload = "netshare e2e " + Guid.NewGuid();
        await File.WriteAllTextAsync(sendPath, payload, Encoding.UTF8);
        var size = new FileInfo(sendPath).Length;

        await using var host = new InternetSession();
        await using var guest = new InternetSession();

        // --- Pairing phase ---
        await host.StartHostAsync(code, new[] { new SharedFileInfo("hello.txt", size) });
        AssertNotFailed(host, "host connect");
        await guest.StartGuestAsync(code);
        AssertNotFailed(guest, "guest connect");

        await WaitFor(() => host.State is PairingState.Confirming, host, "host Confirming");
        await WaitFor(() => guest.State is PairingState.Confirming, guest, "guest Confirming");

        var hostPhrase = ((PairingState.Confirming)host.State).Phrase;
        var guestPhrase = ((PairingState.Confirming)guest.State).Phrase;
        Assert.Equal(hostPhrase, guestPhrase);

        host.ConfirmLocalPairing();
        guest.ConfirmLocalPairing();
        await WaitFor(() => host.State is PairingState.Paired, host, "host Paired");
        await WaitFor(() => guest.State is PairingState.Paired, guest, "guest Paired");
        _out.WriteLine("paired OK");

        // --- Transfer phase (encrypt=true forces the MQTT relay; no WebRTC needed) ---
        await WaitFor(() => guest.RemoteFiles.Count == 1, guest, "guest manifest");
        var expected = guest.RemoteFiles.ToList();

        var receiveRoot = Path.Combine(tempRoot, "recv");
        Directory.CreateDirectory(receiveRoot);

        var guestTask = guest.PrepareGuestFileSinkAsync(
            receiveRoot, expected, encryptFileTransfer: true, beginTransfer: true);
        var hostTask = host.StartHostFileTransferAsync(
            new[] { new LocalShareEntry(sendPath, "hello.txt", size) },
            encryptFileTransfer: true);

        await WaitFor(
            () => guest.IsTransferComplete || guest.TransferFailReason is not null,
            guest, "guest transfer terminal", timeoutSec: 120);
        Assert.Null(guest.TransferFailReason);
        Assert.True(guest.IsTransferComplete, "guest transfer complete");

        var saved = guest.SavedFiles.Single();
        Assert.Equal(payload, await File.ReadAllTextAsync(saved.LocalPath, Encoding.UTF8));
        _out.WriteLine($"transfer OK → {saved.LocalPath}");

        await Task.WhenAny(Task.WhenAll(hostTask, guestTask), Task.Delay(5000));
        Directory.Delete(tempRoot, recursive: true);
    }

    private static void AssertNotFailed(InternetSession s, string stage)
    {
        if (s.State is PairingState.Failed f)
            Assert.Fail($"{stage} failed: {f.Reason}");
    }

    private async Task WaitFor(
        Func<bool> condition, InternetSession session, string what, int timeoutSec = 60)
    {
        var sw = Stopwatch.StartNew();
        while (sw.Elapsed < TimeSpan.FromSeconds(timeoutSec))
        {
            if (condition()) return;
            if (session.State is PairingState.Failed f)
                Assert.Fail($"{what}: session failed — {f.Reason}");
            await Task.Delay(150);
        }
        Assert.Fail($"{what}: timed out after {timeoutSec}s (state {session.State.GetType().Name})");
    }
}
