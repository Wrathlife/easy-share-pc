using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EasyShare.Protocol;

namespace EasyShare.Desktop;

public sealed class AppSettingsStore
{
    private readonly string _path;
    private readonly object _gate = new();
    private Data _data;

    public AppSettingsStore()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Netshare");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "settings.json");
        _data = Load();
        if (string.IsNullOrWhiteSpace(_data.LocalDeviceId))
        {
            _data.LocalDeviceId = Guid.NewGuid().ToString();
            Save();
        }
    }

    public string LocalDeviceId
    {
        get { lock (_gate) return _data.LocalDeviceId; }
    }

    public bool EncryptFileTransfer
    {
        get { lock (_gate) return _data.EncryptFileTransfer; }
        set { lock (_gate) { _data.EncryptFileTransfer = value; Save(); } }
    }

    public string ReceiveFolder => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        "Downloads",
        "Netshare");

    public IReadOnlyList<TrustedDevice> List()
    {
        lock (_gate)
            return _data.Devices.OrderByDescending(d => d.LastUsedAtEpochMs).ToList();
    }

    public TrustedAddResult Add(TrustedDevice device)
    {
        lock (_gate)
        {
            var result = TrustedDevices.Add(_data.Devices, device, TrustedDevices.PaidCap);
            if (result is TrustedAddResult.Ok ok)
            {
                _data.Devices = ok.Devices.ToList();
                Save();
            }
            return result;
        }
    }

    public bool Rename(string pairId, string rawName)
    {
        lock (_gate)
        {
            var updated = TrustedDevices.Rename(_data.Devices, pairId, rawName);
            if (updated is null) return false;
            _data.Devices = updated.ToList();
            Save();
            return true;
        }
    }

    public void Remove(string pairId)
    {
        lock (_gate)
        {
            _data.Devices = TrustedDevices.Remove(_data.Devices, pairId).ToList();
            Save();
        }
    }

    public void TouchLastUsed(string pairId)
    {
        lock (_gate)
        {
            _data.Devices = TrustedDevices.TouchLastUsed(
                _data.Devices, pairId, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()).ToList();
            Save();
        }
    }

    private Data Load()
    {
        try
        {
            if (!File.Exists(_path)) return new Data();
            var json = File.ReadAllText(_path);
            var data = JsonSerializer.Deserialize<Data>(json) ?? new Data();
            if (!string.IsNullOrWhiteSpace(data.DevicesProtected))
            {
                data.Devices = UnprotectDevices(data.DevicesProtected) ?? new List<TrustedDevice>();
                data.DevicesProtected = null;
            }
            return data;
        }
        catch
        {
            return new Data();
        }
    }

    private void Save()
    {
        var toWrite = new Data
        {
            LocalDeviceId = _data.LocalDeviceId,
            EncryptFileTransfer = _data.EncryptFileTransfer,
            DevicesProtected = ProtectDevices(_data.Devices)
        };
        var json = JsonSerializer.Serialize(toWrite, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_path, json);
    }

    private const string DpapiEntropy = "Netshare.trusted-devices.v1";

    private static string ProtectDevices(List<TrustedDevice> devices)
    {
        var json = JsonSerializer.Serialize(devices);
        var bytes = Encoding.UTF8.GetBytes(json);
        var protectedBytes = ProtectedData.Protect(
            bytes, Encoding.UTF8.GetBytes(DpapiEntropy), DataProtectionScope.CurrentUser);
        return Convert.ToBase64String(protectedBytes);
    }

    private static List<TrustedDevice>? UnprotectDevices(string blob)
    {
        try
        {
            var protectedBytes = Convert.FromBase64String(blob);
            var bytes = ProtectedData.Unprotect(
                protectedBytes, Encoding.UTF8.GetBytes(DpapiEntropy), DataProtectionScope.CurrentUser);
            return JsonSerializer.Deserialize<List<TrustedDevice>>(Encoding.UTF8.GetString(bytes));
        }
        catch
        {
            return null;
        }
    }

    private sealed class Data
    {
        public string LocalDeviceId { get; set; } = "";
        public bool EncryptFileTransfer { get; set; }
        public List<TrustedDevice> Devices { get; set; } = new();
        public string? DevicesProtected { get; set; }
    }
}

internal static class ShareCollector
{
    public static List<LocalShareEntry> FromFiles(IEnumerable<string> paths)
    {
        var list = new List<LocalShareEntry>();
        foreach (var path in paths)
        {
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists) continue;
                list.Add(new LocalShareEntry(info.FullName, info.Name, info.Length));
                if (list.Count >= ProtocolPaths.MaxManifestFiles) break;
            }
            catch { /* skip unreadable */ }
        }
        return list;
    }

    public static List<LocalShareEntry> FromFolder(string root)
    {
        var list = new List<LocalShareEntry>();
        if (!Directory.Exists(root)) return list;
        foreach (var path in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists) continue;
                var rel = Path.GetRelativePath(root, path).Replace('\\', '/');
                if (ProtocolPaths.SanitizeWirePath(rel) is null) continue;
                list.Add(new LocalShareEntry(info.FullName, rel, info.Length));
                if (list.Count >= ProtocolPaths.MaxManifestFiles) break;
            }
            catch { /* skip unreadable */ }
        }
        return list;
    }
}
