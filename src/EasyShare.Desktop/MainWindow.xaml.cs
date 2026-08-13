using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using EasyShare.Protocol;
using Microsoft.Win32;

namespace EasyShare.Desktop;

public partial class MainWindow : Window
{
    private InternetSession? _session;
    private readonly MainVm _vm = new();
    private List<LocalShareEntry> _shareEntries = new();
    private string? _receiveFolder;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _vm;
        ShowHome();
    }

    private void ShowHome()
    {
        HomePanel.Visibility = Visibility.Visible;
        SharePanel.Visibility = Visibility.Collapsed;
        ReceivePanel.Visibility = Visibility.Collapsed;
    }

    private void OnShareClick(object sender, RoutedEventArgs e)
    {
        HomePanel.Visibility = Visibility.Collapsed;
        SharePanel.Visibility = Visibility.Visible;
        ReceivePanel.Visibility = Visibility.Collapsed;
        _vm.Status = "Pick files to share.";
        _vm.CodeDisplay = "";
        _vm.Phrase = "";
        _vm.ProgressText = "";
    }

    private void OnReceiveClick(object sender, RoutedEventArgs e)
    {
        HomePanel.Visibility = Visibility.Collapsed;
        SharePanel.Visibility = Visibility.Collapsed;
        ReceivePanel.Visibility = Visibility.Visible;
        _vm.Status = "Enter the share code from the other device.";
        _vm.Phrase = "";
        _vm.ProgressText = "";
    }

    private void OnBackHome(object sender, RoutedEventArgs e)
    {
        _ = StopSessionAsync();
        ShowHome();
    }

    private void OnPickFiles(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Multiselect = true,
            Title = "Choose files to share"
        };
        if (dlg.ShowDialog() != true) return;
        _shareEntries = dlg.FileNames.Select(path =>
        {
            var info = new FileInfo(path);
            return new LocalShareEntry(path, info.Name, info.Length);
        }).ToList();
        _vm.Status = $"{_shareEntries.Count} file(s) selected.";
    }

    private async void OnStartShare(object sender, RoutedEventArgs e)
    {
        if (_shareEntries.Count == 0)
        {
            _vm.Status = "Pick at least one file first.";
            return;
        }
        await StopSessionAsync();
        var code = PairingCode.GenerateShort();
        _vm.CodeDisplay = PairingCode.FormatForDisplay(code);
        _vm.Status = "Connecting…";
        _vm.CanConfirm = false;
        _session = WireSession();
        var files = _shareEntries.Select(e => new SharedFileInfo(e.RelativePath, e.SizeBytes)).ToList();
        await _session.StartHostAsync(code, files);
    }

    private async void OnStartReceive(object sender, RoutedEventArgs e)
    {
        var code = PairingCode.Normalize(ReceiveCodeBox.Text ?? "");
        if (!PairingCode.IsValidShort(code))
        {
            _vm.Status = "Invalid share code format.";
            return;
        }
        var folderDlg = new OpenFolderDialog { Title = "Choose folder to save received files" };
        if (folderDlg.ShowDialog() != true) return;
        _receiveFolder = folderDlg.FolderName;
        await StopSessionAsync();
        _vm.Status = "Connecting…";
        _vm.CanConfirm = false;
        _session = WireSession();
        await _session.StartGuestAsync(code);
    }

    private void OnConfirm(object sender, RoutedEventArgs e) => _session?.ConfirmLocalPairing();

    private void OnReject(object sender, RoutedEventArgs e) => _session?.RejectLocalPairing();

    private InternetSession WireSession()
    {
        var session = new InternetSession();
        session.StateChanged += state => Dispatcher.Invoke(() => OnState(state));
        session.RemoteFilesChanged += files => Dispatcher.Invoke(() =>
        {
            _vm.Status = files.Count > 0
                ? $"Incoming: {files.Count} file(s), {FormatBytes(files.Sum(f => Math.Max(0, f.SizeBytes)))}"
                : _vm.Status;
        });
        session.ProgressChanged += p => Dispatcher.Invoke(() =>
        {
            if (p is null) { _vm.ProgressText = ""; return; }
            var pct = p.BytesTotal > 0 ? (100.0 * p.BytesDone / p.BytesTotal) : 0;
            _vm.ProgressValue = pct;
            var speed = p.SpeedBytesPerSec > 0 ? $"{FormatBytes(p.SpeedBytesPerSec)}/s" : "";
            _vm.ProgressText = $"{pct:0.#}%  {FormatBytes(p.BytesDone)} / {FormatBytes(p.BytesTotal)}  {speed}";
        });
        session.TransferCompleted += () => Dispatcher.Invoke(() =>
        {
            _vm.Status = "Transfer complete.";
            _vm.ProgressValue = 100;
        });
        session.TransferFailed += reason => Dispatcher.Invoke(() => _vm.Status = "Failed: " + reason);
        session.SavedFilesChanged += files => Dispatcher.Invoke(() =>
        {
            if (files.Count > 0)
                _vm.Status = $"Saved {files.Count} file(s).";
        });
        return session;
    }

    private async void OnState(PairingState state)
    {
        switch (state)
        {
            case PairingState.Connecting:
                _vm.Status = "Connecting…";
                break;
            case PairingState.Waiting:
                _vm.Status = _session?.State is PairingState.Waiting && !string.IsNullOrEmpty(_vm.CodeDisplay)
                    ? "Waiting for the other device… Enter this code there."
                    : "Waiting for host…";
                break;
            case PairingState.Confirming c:
                _vm.Phrase = c.Phrase;
                _vm.CanConfirm = !c.LocalConfirmed;
                _vm.Status = c.LocalConfirmed
                    ? (c.PeerConfirmed ? "Paired." : "Waiting for the other device to confirm…")
                    : "Do both devices show the same phrase?";
                break;
            case PairingState.Paired:
                _vm.CanConfirm = false;
                _vm.Status = "Paired — starting transfer…";
                await BeginTransferAfterPairedAsync();
                break;
            case PairingState.Failed f:
                _vm.Status = f.Reason;
                _vm.CanConfirm = false;
                break;
        }
    }

    private async Task BeginTransferAfterPairedAsync()
    {
        if (_session is null) return;
        var encrypt = EncryptToggle.IsChecked == true || ReceiveEncryptToggle.IsChecked == true;
        if (!string.IsNullOrEmpty(_vm.CodeDisplay) && _shareEntries.Count > 0)
        {
            await _session.StartHostFileTransferAsync(_shareEntries, encrypt);
        }
        else if (_receiveFolder is not null)
        {
            var expected = _session.RemoteFiles.ToList();
            await _session.PrepareGuestFileSinkAsync(_receiveFolder, expected, encrypt, beginTransfer: true);
        }
    }

    private async Task StopSessionAsync()
    {
        if (_session is not null)
        {
            await _session.StopAsync();
            await _session.DisposeAsync();
            _session = null;
        }
    }

    private static string FormatBytes(long n)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double v = Math.Max(0, n);
        var i = 0;
        while (v >= 1024 && i < units.Length - 1) { v /= 1024; i++; }
        return $"{v:0.##} {units[i]}";
    }

    protected override async void OnClosed(EventArgs e)
    {
        await StopSessionAsync();
        base.OnClosed(e);
    }
}

public sealed class MainVm : INotifyPropertyChanged
{
    private string _status = "Share or receive files with Android — no account, no ads.";
    private string _codeDisplay = "";
    private string _phrase = "";
    private string _progressText = "";
    private double _progressValue;
    private bool _canConfirm;

    public event PropertyChangedEventHandler? PropertyChanged;

    public string Status { get => _status; set => Set(ref _status, value); }
    public string CodeDisplay { get => _codeDisplay; set => Set(ref _codeDisplay, value); }
    public string Phrase { get => _phrase; set => Set(ref _phrase, value); }
    public string ProgressText { get => _progressText; set => Set(ref _progressText, value); }
    public double ProgressValue { get => _progressValue; set => Set(ref _progressValue, value); }
    public bool CanConfirm { get => _canConfirm; set => Set(ref _canConfirm, value); }

    private void Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (Equals(field, value)) return;
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
