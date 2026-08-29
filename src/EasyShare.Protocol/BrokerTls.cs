using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MQTTnet.Client;

namespace EasyShare.Protocol;

/// <summary>System PKIX plus SPKI pins for broker.emqx.io — parity with Android MqttSsl.</summary>
public static class BrokerTls
{
    private static readonly HashSet<string> SpkiPins = new(StringComparer.Ordinal)
    {
        "KTYj5LiWqYowwWQsMEgva7C/CJQj8tDQ0Dk9I6is1ZE=",
        "E3tYcwo9CiqATmKtpMLW5V+pzIq+ZoDmpXSiJlXGmTo=",
        "i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY="
    };

    public static bool IsTrusted(MqttClientCertificateValidationEventArgs args)
    {
        if (args.SslPolicyErrors != SslPolicyErrors.None)
        {
            // #region agent log
            AgentDebug.Log("tls-pin", "BrokerTls.cs:IsTrusted", "chain/name failed",
                new { errors = args.SslPolicyErrors.ToString() }, "C");
            // #endregion
            return false;
        }
        var pins = new List<string>();
        if (args.Certificate is not null)
            pins.Add(SpkiSha256B64(args.Certificate));
        if (args.Chain is not null)
        {
            foreach (var el in args.Chain.ChainElements)
                pins.Add(SpkiSha256B64(el.Certificate));
        }
        var ok = pins.Any(p => SpkiPins.Contains(p));
        // #region agent log
        AgentDebug.Log("tls-pin", "BrokerTls.cs:IsTrusted", ok ? "pin matched" : "pin mismatch",
            new { pinCount = pins.Count }, "C");
        // #endregion
        return ok;
    }

    private static string SpkiSha256B64(X509Certificate cert)
    {
        using var c2 = cert as X509Certificate2 ?? new X509Certificate2(cert);
        var spki = c2.PublicKey.ExportSubjectPublicKeyInfo();
        return Convert.ToBase64String(SHA256.HashData(spki));
    }
}
