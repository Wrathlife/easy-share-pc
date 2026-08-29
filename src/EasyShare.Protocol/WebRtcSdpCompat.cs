namespace EasyShare.Protocol;

using System.Text;
using System.Text.RegularExpressions;

/// <summary>
/// Embed ICE into SDP so Android libwebrtc can connect even when it ignores
/// trickle ICE from this peer (legacy SIPSorcery-era safeguard on the APK).
/// </summary>
public static class WebRtcSdpCompat
{
    private static readonly Regex CandidateLine = new(
        @"^a=candidate:(.*)$",
        RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.Compiled);

    private static readonly Regex EndOfCandidates = new(
        @"\r?\na=end-of-candidates\s*",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex IceOptions = new(
        @"^a=ice-options:[^\r\n]*",
        RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.Compiled);

    public static string WithEmbeddedCandidates(string sdp, IReadOnlyList<IceCandidateDto> ice)
    {
        if (string.IsNullOrWhiteSpace(sdp)) return sdp;
        var existing = CandidateBodies(sdp);
        var toAdd = new List<string>();
        foreach (var c in ice)
        {
            var line = ToSdpCandidateLine(c.Sdp);
            if (line is null) continue;
            var body = line[2..].Trim().ToLowerInvariant();
            if (existing.Contains(body)) continue;
            existing.Add(body);
            toAdd.Add(line);
        }

        var outSdp = EndOfCandidates.Replace(sdp, "");
        if (toAdd.Count > 0)
        {
            var sb = new StringBuilder(outSdp.TrimEnd('\r', '\n'));
            sb.Append("\r\n");
            foreach (var line in toAdd)
                sb.Append(line).Append("\r\n");
            outSdp = sb.ToString();
        }
        return EnsureEndOfCandidates(NormalizeForLibwebrtc(outSdp));
    }

    /// <summary>Soften ice-options (ice2) so Android libwebrtc treats us as a normal peer.</summary>
    public static string NormalizeForLibwebrtc(string sdp)
    {
        if (string.IsNullOrWhiteSpace(sdp)) return sdp;
        return IceOptions.Replace(sdp, "a=ice-options:trickle");
    }

    public static string? ToSdpCandidateLine(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var line = raw.Trim();
        if (line.StartsWith("a=", StringComparison.OrdinalIgnoreCase))
            line = line[2..].Trim();
        if (!line.StartsWith("candidate:", StringComparison.OrdinalIgnoreCase))
            line = "candidate:" + line;
        return "a=" + line;
    }

    public static string EnsureEndOfCandidates(string sdp)
    {
        if (sdp.Contains("a=end-of-candidates", StringComparison.OrdinalIgnoreCase))
            return sdp;
        return sdp.TrimEnd('\r', '\n') + "\r\n" + "a=end-of-candidates\r\n";
    }

    /// <summary>Set or replace a=max-message-size for DataChannel negotiation.</summary>
    public static string WithMaxMessageSize(string sdp, int maxMessageSize = DcChunkLimits.LocalMaxMessageSize)
    {
        if (string.IsNullOrWhiteSpace(sdp) || maxMessageSize <= 0) return sdp;
        var attr = $"a=max-message-size:{maxMessageSize}";
        if (Regex.IsMatch(sdp, @"^a=max-message-size:\d+\s*$", RegexOptions.IgnoreCase | RegexOptions.Multiline))
        {
            return Regex.Replace(sdp, @"^a=max-message-size:\d+\s*$", attr,
                RegexOptions.IgnoreCase | RegexOptions.Multiline);
        }
        var withPort = Regex.Replace(sdp, @"^(a=sctp-port:\d+)\s*$", $"$1\r\n{attr}",
            RegexOptions.IgnoreCase | RegexOptions.Multiline);
        if (withPort != sdp) return withPort;
        return sdp.TrimEnd('\r', '\n') + "\r\n" + attr + "\r\n";
    }

    public static int? ParseMaxMessageSize(string sdp)
    {
        var m = Regex.Match(sdp ?? "", @"^a=max-message-size:(\d+)\s*$",
            RegexOptions.IgnoreCase | RegexOptions.Multiline);
        if (!m.Success) return null;
        return int.TryParse(m.Groups[1].Value, out var n) && n > 0 ? n : null;
    }

    private static HashSet<string> CandidateBodies(string sdp)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match m in CandidateLine.Matches(sdp))
            set.Add(("candidate:" + m.Groups[1].Value.Trim()).ToLowerInvariant());
        return set;
    }
}
