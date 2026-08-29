using System.Text.Json;

namespace EasyShare.Protocol;

internal static class AgentDebug
{
    private const string SessionId = "eccb22";
    private static readonly string LogPath =
        Path.Combine(@"D:\AI-SANDBOX\projects\easy-share-pc", "debug-eccb22.log");

    public static void Log(string hypothesisId, string location, string message, object data, string? runId = null)
    {
        // #region agent log
        try
        {
            var payload = new Dictionary<string, object?>
            {
                ["sessionId"] = SessionId,
                ["hypothesisId"] = hypothesisId,
                ["location"] = location,
                ["message"] = message,
                ["data"] = data,
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };
            if (runId is not null) payload["runId"] = runId;
            File.AppendAllText(LogPath, JsonSerializer.Serialize(payload) + "\n");
        }
        catch { /* debug ingest must never break transfer */ }
        // #endregion
    }
}
