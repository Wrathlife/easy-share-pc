using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;
using EasyShare.Protocol;
using Microsoft.Win32;

namespace EasyShare.Desktop;

public partial class MainWindow : Window
{
    private readonly AppSettingsStore _store = new();
    private readonly MainVm _vm = new();
    private readonly DispatcherTimer _tick = new() { Interval = TimeSpan.FromMilliseconds(250) };
    private InternetSession? _live;
    private InternetSession? _xfer;
    private PairPhase _phase = PairPhase.Hub;
    private string _liveCode = "";
    private long _codeStartedAtMs;
    private bool _joiningTheirCode;
    private long _joinStartedAtMs;
    private int _liveStartGen;
    private TrustedDevice? _sessionPair;
    private TrustedDevice? _sendTarget;
    private List<LocalShareEntry> _entries = new();
    private string _incomingPeerName = "Trusted device";
    private bool _skipSavePrompt;
    private string _pendingTrustLabel = "";
    private bool _checkingTrusted;
    private long _unsavedDeadlineMs;
    private bool _unsavedExpiredPending;
    private DeviceRow? _renameTarget;

    private enum PairPhase
    {
        Hub, Confirming, ConfirmPairing, Paired,
        Sending, AcceptIncoming, Receiving, SendDone, ReceiveDone
    }

    public MainWindow()
    {
        InitializeComponent();
        _vm.EncryptEnabled = _store.EncryptFileTransfer;
        _vm.AboutVersion = "Version " + (typeof(App).Assembly.GetName().Version?.ToString(3) ?? "1.0.0");
        DataContext = _vm;
        _tick.Tick += (_, _) => OnTick();
        Directory.CreateDirectory(_store.ReceiveFolder);
        RefreshDevices();
        ShowHome();
    }

    private void ShowHome()
    {
        HomePanel.Visibility = Visibility.Visible;
        PairPanel.Visibility = Visibility.Collapsed;
        AboutPanel.Visibility = Visibility.Collapsed;
        _tick.Stop();
    }

    private void ShowAbout()
    {
        HomePanel.Visibility = Visibility.Collapsed;
        PairPanel.Visibility = Visibility.Collapsed;
        AboutPanel.Visibility = Visibility.Visible;
    }

    private async void OnPairClick(object sender, RoutedEventArgs e)
    {
        HomePanel.Visibility = Visibility.Collapsed;
        AboutPanel.Visibility = Visibility.Collapsed;
        PairPanel.Visibility = Visibility.Visible;
        TheirCodeBox.Text = "";
        await EnterPairHubAsync(remint: true);
        _tick.Start();
    }

    private void OnAboutClick(object sender, RoutedEventArgs e) => ShowAbout();
    private void OnAboutBack(object sender, RoutedEventArgs e) => ShowHome();

    private async void OnPairBack(object sender, RoutedEventArgs e)
    {
        switch (_phase)
        {
            case PairPhase.Hub:
            case PairPhase.Paired:
            case PairPhase.SendDone:
            case PairPhase.ReceiveDone:
                await LeaveToHomeAsync();
                break;
            case PairPhase.ConfirmPairing:
                SkipSaveAndPair();
                break;
            default:
                await ReturnToHubAsync();
                break;
        }
    }

    private void OnEncryptToggleLoaded(object sender, RoutedEventArgs e)
    {
        if (sender is not ToggleButton button)
            return;
        try
        {
            button.ApplyTemplate();
            var on = button.IsChecked == true;
            // Template freezables are shared/read-only — assign new instances, never mutate.
            if (button.Template.FindName("thumb", button) is Border thumb)
                thumb.RenderTransform = new TranslateTransform(on ? 20 : 0, 0);
            if (button.Template.FindName("track", button) is Border track)
            {
                track.Background = new SolidColorBrush(
                    on ? Color.FromRgb(0x1A, 0x73, 0xE8) : Color.FromRgb(0xDA, 0xDC, 0xE0));
            }
        }
        catch
        {
            // Template thumb animation is best-effort.
        }
    }

    private void OnEncryptChanged(object sender, RoutedEventArgs e)
    {
        _store.EncryptFileTransfer = _vm.EncryptEnabled;
    }

    private void OnOpenReceivedClick(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(_store.ReceiveFolder);
        Process.Start(new ProcessStartInfo
        {
            FileName = _store.ReceiveFolder,
            UseShellExecute = true
        });
    }

    private bool _updatingTheirCode;

    private void OnTheirCodeChanged(object sender, TextChangedEventArgs e)
    {
        if (_updatingTheirCode) return;
        var caret = TheirCodeBox.CaretIndex;
        var incoming = TheirCodeBox.Text ?? "";
        // Wire form only in the box — inserting a hyphen here jumps the caret on the digit half.
        var raw = PairingCode.SanitizeTyping(incoming);
        if (incoming != raw)
        {
            var atEnd = caret >= incoming.Length;
            var rawBefore = PairingCode.SanitizeTyping(
                incoming[..Math.Min(caret, incoming.Length)]).Length;
            _updatingTheirCode = true;
            TheirCodeBox.Text = raw;
            TheirCodeBox.CaretIndex = atEnd
                ? raw.Length
                : Math.Min(raw.Length, rawBefore);
            _updatingTheirCode = false;
        }
        _vm.CanJoin = PairingCode.IsValidShort(raw);
    }

    private void OnCopyCode(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_liveCode)) return;
        Clipboard.SetText(PairingCode.FormatForDisplay(_liveCode));
        _vm.Status = "Code copied";
    }

    private async void OnJoin(object sender, RoutedEventArgs e)
    {
        var normalized = PairingCode.Normalize(TheirCodeBox.Text ?? "");
        if (!PairingCode.IsValidShort(normalized))
        {
            _vm.Status = "Enter a valid pairing code";
            return;
        }
        _joiningTheirCode = true;
        _joinStartedAtMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        _vm.Status = "Connecting to the pairing server…";
        ApplyHubVisibility();
        // Paint the joining UI before MQTT (TLS can block the UI thread and blank the window).
        await Dispatcher.InvokeAsync(() => { }, System.Windows.Threading.DispatcherPriority.Render);

        Interlocked.Increment(ref _liveStartGen);
        var gen = _liveStartGen;
        var previous = _live;
        _live = null;
        if (previous is not null)
        {
            previous.StateChanged -= OnLiveState;
            previous.EphemeralPairChanged -= OnEphemeral;
            previous.TrustHandshakeChanged -= OnTrustHandshake;
        }

        InternetSession session;
        try
        {
            if (previous is not null)
                await Task.Run(async () => await previous.StopAsync().ConfigureAwait(false))
                    .ConfigureAwait(true);
            if (gen != _liveStartGen || !_joiningTheirCode) return;

            session = new InternetSession();
            WireLive(session);
            _live = session;
            await Task.Run(async () => await session.StartGuestAsync(normalized).ConfigureAwait(false))
                .ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            if (gen != _liveStartGen) return;
            _joiningTheirCode = false;
            _joinStartedAtMs = 0;
            _vm.Status = ex.Message;
            ApplyHubVisibility();
            _ = StartLiveHostAsync(newCode: false);
        }
    }

    private void OnConfirm(object sender, RoutedEventArgs e) => _live?.ConfirmLocalPairing();

    private void OnReject(object sender, RoutedEventArgs e) => _live?.RejectLocalPairing();

    private void OnSaveDevice(object sender, RoutedEventArgs e)
    {
        _pendingTrustLabel = _vm.SaveDeviceName;
        _live?.RequestTrustBind(_store.LocalDeviceId, AdvertisedName());
    }

    private void OnSkipSave(object sender, RoutedEventArgs e) => SkipSaveAndPair();

    private void OnAcceptIncoming(object sender, RoutedEventArgs e) => _xfer?.AcceptTrustedIncoming();

    private async void OnDeclineIncoming(object sender, RoutedEventArgs e)
    {
        _xfer?.DeclineTrustedIncoming();
        await ReturnToHubAsync();
    }

    private void OnCancelTransfer(object sender, RoutedEventArgs e) => _xfer?.CancelTransfer();

    private async void OnDismissResult(object sender, RoutedEventArgs e)
    {
        if (_unsavedExpiredPending)
            await RemintPairAsync(TrustBindPolicy.UnsavedExpiredReason);
        else
            await ReturnToHubAsync();
    }

    private void OnOpenResultFile(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string path } || string.IsNullOrWhiteSpace(path)) return;
        if (!File.Exists(path)) return;
        Process.Start(new ProcessStartInfo { FileName = path, UseShellExecute = true });
    }

    private void OnSendFiles(object sender, RoutedEventArgs e)
    {
        var device = _sessionPair;
        if (device is null) return;
        PromptSend(device, folder: false);
    }

    private void OnSendFolder(object sender, RoutedEventArgs e)
    {
        var device = _sessionPair;
        if (device is null) return;
        PromptSend(device, folder: true);
    }

    private void OnSendToDevice(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: DeviceRow row }) return;
        PromptSend(row.Device, folder: false);
    }

    private void OnRenameDevice(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: DeviceRow row }) return;
        _renameTarget = row;
        _vm.RenameValue = row.Device.PeerName;
        _vm.ShowRename = true;
    }

    private void OnRemoveDevice(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: DeviceRow row }) return;
        if (_sessionPair?.PairId == row.Device.PairId) _sessionPair = null;
        _store.Remove(row.Device.PairId);
        RefreshDevices();
        _ = RestartInboxAsync();
    }

    private void OnRenameSave(object sender, RoutedEventArgs e)
    {
        if (_renameTarget is null) return;
        if (!_store.Rename(_renameTarget.Device.PairId, _vm.RenameValue))
        {
            _vm.Status = $"Enter a name (max {TrustedDevices.NameMax} characters)";
            return;
        }
        _renameTarget = null;
        _vm.ShowRename = false;
        RefreshDevices();
    }

    private void OnRenameCancel(object sender, RoutedEventArgs e)
    {
        _renameTarget = null;
        _vm.ShowRename = false;
    }

    private async Task EnterPairHubAsync(bool remint)
    {
        _joiningTheirCode = false;
        _joinStartedAtMs = 0;
        _sendTarget = null;
        _entries = new();
        _checkingTrusted = false;
        _skipSavePrompt = false;
        _pendingTrustLabel = "";
        _phase = PairPhase.Hub;
        TheirCodeBox.Text = "";
        _vm.CanJoin = false;
        // Stale "Online — …" text from the previous visit changes the content height
        // while the new session spins up; clear it so re-entry lays out once.
        _vm.Status = "";
        ApplyPhaseUi();
        if (_live is not null &&
            _live.State is not PairingState.Paired and not PairingState.Confirming)
        {
            await _live.StopAsync();
        }
        if (remint)
            await StartLiveHostAsync(newCode: true);
        await RestartInboxAsync();
    }

    private async Task ReturnToHubAsync()
    {
        var transferring = _phase is PairPhase.Sending or PairPhase.Receiving;
        _joiningTheirCode = false;
        _joinStartedAtMs = 0;
        TheirCodeBox.Text = "";
        _sendTarget = null;
        _entries = new();
        _checkingTrusted = false;
        _skipSavePrompt = false;
        _pendingTrustLabel = "";
        _phase = PairPhase.Hub;
        ApplyPhaseUi();
        // Always stop + remint: a leftover Paired live session hides ShowLiveCode and
        // leaves the hub looking empty after cancel/transfer failure.
        if (_live is not null) await _live.StopAsync();
        await StartLiveHostAsync(newCode: true);
        if (transferring)
            _xfer?.CancelTransfer();
        else
            await StopXferAsync();
        await RestartInboxAsync();
    }

    private async Task CancelJoinAndRemintAsync()
    {
        ApplyHubVisibility();
        if (_live is not null) await _live.StopAsync();
        _live = null;
        await StartLiveHostAsync(newCode: false);
    }

    private async Task RemintPairAsync(string? reason = null)
    {
        if (reason is not null) _vm.Status = reason;
        _skipSavePrompt = false;
        _pendingTrustLabel = "";
        _sessionPair = null;
        _unsavedDeadlineMs = 0;
        _unsavedExpiredPending = false;
        _joiningTheirCode = false;
        _joinStartedAtMs = 0;
        TheirCodeBox.Text = "";
        _sendTarget = null;
        _entries = new();
        _checkingTrusted = false;
        _phase = PairPhase.Hub;
        ApplyPhaseUi();
        if (_live is not null) await _live.StopAsync();
        await StopXferAsync();
        await RestartInboxAsync();
        await StartLiveHostAsync(newCode: true);
    }

    private async Task LeaveToHomeAsync()
    {
        _tick.Stop();
        if (_live is not null) await _live.StopAsync();
        await StopXferAsync();
        _live = null;
        _sessionPair = null;
        ShowHome();
    }

    private async Task StartLiveHostAsync(bool newCode)
    {
        if (_joiningTheirCode) return;
        if (_phase is PairPhase.Sending or PairPhase.Receiving or PairPhase.AcceptIncoming
            or PairPhase.ConfirmPairing or PairPhase.Paired)
            return;
        if (_live?.IsPeerJoined == true) return;
        if (_live?.State is PairingState.Confirming or PairingState.Paired) return;

        if (newCode)
        {
            _liveCode = PairingCode.GenerateShort();
            _codeStartedAtMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }
        _vm.CodeDisplay = PairingCode.FormatForDisplay(_liveCode);

        var gen = Interlocked.Increment(ref _liveStartGen);
        if (_live is not null)
        {
            try { await _live.StopAsync(); } catch { /* ignore */ }
            _live = null;
        }
        if (gen != _liveStartGen || _joiningTheirCode) return;

        var session = new InternetSession();
        WireLive(session);
        _live = session;
        try
        {
            await session.StartHostPairingAsync(_liveCode);
        }
        catch (Exception ex)
        {
            if (ReferenceEquals(_live, session))
                _vm.Status = "Couldn’t start pairing: " + ex.Message;
            return;
        }
        if (gen != _liveStartGen || _joiningTheirCode || !ReferenceEquals(_live, session))
        {
            try { await session.StopAsync(); } catch { /* ignore */ }
            if (ReferenceEquals(_live, session)) _live = null;
            return;
        }
        ApplyHubVisibility();
    }

    private async Task RestartInboxAsync()
    {
        RefreshDevices();
        // Never stomp an in-flight trusted send/receive — concurrent inbox reconnect was
        // treating our own host ready/manifest as TrustedIncoming (Accept UI while sending).
        if (_checkingTrusted ||
            _phase is PairPhase.Sending or PairPhase.Receiving or PairPhase.AcceptIncoming)
        {
            return;
        }
        var devices = InboxDevices();
        if (devices.Count == 0)
        {
            await StopXferAsync();
            return;
        }
        switch (_xfer?.State)
        {
            case PairingState.Paired:
            case PairingState.TrustedIncoming:
            case PairingState.Waiting:
            case PairingState.Connecting:
                return;
        }
        await StopXferAsync();
        _xfer = new InternetSession();
        WireXfer(_xfer);
        await _xfer.StartGuestTrustInboxAsync(devices);
    }

    private async Task StopXferAsync()
    {
        if (_xfer is null) return;
        var session = _xfer;
        _xfer = null;
        try { await session.StopAsync(); }
        catch { /* ignore */ }
        try { await session.DisposeAsync(); }
        catch { /* ignore */ }
    }

    private List<TrustedDevice> InboxDevices()
    {
        var saved = _store.List().ToList();
        if (_sessionPair is { } extra && saved.All(d => d.PairId != extra.PairId))
            saved.Insert(0, extra);
        return saved;
    }

    private void PromptSend(TrustedDevice device, bool folder)
    {
        _sendTarget = device;
        if (folder)
        {
            var dlg = new OpenFolderDialog { Title = "Choose a folder to send" };
            if (dlg.ShowDialog() != true)
            {
                _sendTarget = null;
                return;
            }
            var collected = ShareCollector.FromFolder(dlg.FolderName);
            if (collected.Count == 0)
            {
                _vm.Status = "No files found in that folder (empty or inaccessible)";
                _sendTarget = null;
                return;
            }
            _ = BeginSendAsync(device, collected);
        }
        else
        {
            var dlg = new OpenFileDialog { Multiselect = true, Title = "Choose files to send" };
            if (dlg.ShowDialog() != true)
            {
                _sendTarget = null;
                return;
            }
            var collected = ShareCollector.FromFiles(dlg.FileNames);
            if (collected.Count == 0)
            {
                _vm.Status = "Could not read selected files";
                _sendTarget = null;
                return;
            }
            _ = BeginSendAsync(device, collected);
        }
    }

    private async Task BeginSendAsync(TrustedDevice target, List<LocalShareEntry> files)
    {
        if (files.Count == 0)
        {
            _vm.Status = "Pick at least one file or folder first";
            return;
        }
        if (files.Count > ProtocolPaths.MaxManifestFiles)
        {
            _vm.Status = $"Too many files ({files.Count}). Max {ProtocolPaths.MaxManifestFiles} per share.";
            return;
        }
        _sendTarget = target;
        _entries = files;
        _vm.Status = "";
        await EnsureLiveAsync();
        if (!_live!.IsPeerJoined)
            await _live.StopAsync();
        _store.TouchLastUsed(target.PairId);
        _checkingTrusted = true;
        _vm.CheckingTrusted = true;
        ApplyPhaseUi();
        // Fresh xfer session so a leftover trust-inbox MQTT client cannot see our own
        // host ready/manifest and flip the UI to AcceptIncoming.
        await StopXferAsync();
        _xfer = new InternetSession();
        WireXfer(_xfer);
        var manifest = files.Select(f => new SharedFileInfo(f.RelativePath, f.SizeBytes)).ToList();
        await _xfer.StartHostTrustedAsync(target, manifest);
    }

    private async Task EnsureLiveAsync()
    {
        if (_live is not null) return;
        _live = new InternetSession();
        WireLive(_live);
        await Task.CompletedTask;
    }

    private async Task EnsureXferAsync()
    {
        if (_xfer is not null) return;
        _xfer = new InternetSession();
        WireXfer(_xfer);
        await Task.CompletedTask;
    }

    private void WireLive(InternetSession session)
    {
        session.StateChanged -= OnLiveState;
        session.StateChanged += OnLiveState;
        session.EphemeralPairChanged -= OnEphemeral;
        session.EphemeralPairChanged += OnEphemeral;
        session.TrustHandshakeChanged -= OnTrustHandshake;
        session.TrustHandshakeChanged += OnTrustHandshake;
    }

    private void WireXfer(InternetSession session)
    {
        session.StateChanged -= OnXferState;
        session.StateChanged += OnXferState;
        session.RemoteFilesChanged -= OnXferRemoteFiles;
        session.RemoteFilesChanged += OnXferRemoteFiles;
        session.ProgressChanged -= OnXferProgress;
        session.ProgressChanged += OnXferProgress;
        session.TransferCompleted -= OnXferComplete;
        session.TransferCompleted += OnXferComplete;
        session.TransferFailed -= OnXferFailed;
        session.TransferFailed += OnXferFailed;
        session.SavedFilesChanged -= OnXferSavedFiles;
        session.SavedFilesChanged += OnXferSavedFiles;
    }

    private void OnLiveState(PairingState state)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => OnLiveState(state)); return; }
        switch (state)
        {
            case PairingState.Connecting:
                _vm.Status = "Connecting to the pairing server…";
                break;
            case PairingState.Waiting:
                _vm.Status = _joiningTheirCode
                    ? "Online — waiting for the other device…"
                    : "Online — share this code; keep this screen open until they join.";
                ApplyHubVisibility();
                break;
            case PairingState.Confirming c:
                _joinStartedAtMs = 0;
                if (_phase is PairPhase.Hub or PairPhase.Paired)
                    _phase = PairPhase.Confirming;
                _vm.Phrase = c.Phrase;
                _vm.CanConfirm = !c.LocalConfirmed;
                _vm.ConfirmButtonText = c.LocalConfirmed ? "You confirmed" : "Yes — words match";
                _vm.ConfirmHint = (c.LocalConfirmed, c.PeerConfirmed) switch
                {
                    (true, true) => "Both confirmed",
                    (true, false) => "Waiting for the other device to confirm…",
                    (false, true) => "Other device confirmed — your turn",
                    _ => "Neither device has confirmed yet"
                };
                _vm.Status = "Confirm these are the right devices";
                ApplyPhaseUi();
                break;
            case PairingState.Paired:
                _joinStartedAtMs = 0;
                if (_phase is PairPhase.Confirming or PairPhase.Hub)
                {
                    _skipSavePrompt = false;
                    _phase = PairPhase.ConfirmPairing;
                    _live?.StartEphemeralBind(_store.LocalDeviceId, AdvertisedName());
                    ApplyPhaseUi();
                }
                break;
            case PairingState.Failed f:
                if (_phase is PairPhase.Confirming or PairPhase.ConfirmPairing || _joiningTheirCode)
                {
                    _vm.Status = f.Reason;
                    var wasJoining = _joiningTheirCode;
                    _joiningTheirCode = false;
                    _joinStartedAtMs = 0;
                    if (wasJoining)
                    {
                        ApplyHubVisibility();
                        _ = StartLiveHostAsync(newCode: false);
                    }
                    else if (_phase is not PairPhase.Sending and not PairPhase.Receiving)
                        _ = RemintPairAsync();
                }
                break;
        }
    }

    private void OnEphemeral(EphemeralPair? pair)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => OnEphemeral(pair)); return; }
        if (pair is not null)
            _sessionPair = pair.AsDevice();
        if (_sessionPair is not null &&
            !_checkingTrusted &&
            _phase is not (PairPhase.Sending or PairPhase.Receiving or PairPhase.AcceptIncoming))
            _ = RestartInboxAsync();
        if (_phase == PairPhase.ConfirmPairing && _skipSavePrompt && pair is not null)
        {
            BeginUnsavedCap();
            _phase = PairPhase.Paired;
        }
        ApplyPhaseUi();
    }

    private void OnTrustHandshake(TrustHandshakeState hs)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => OnTrustHandshake(hs)); return; }
        PersistTrustIfComplete();
        if (_phase != PairPhase.ConfirmPairing) return;
        switch (hs)
        {
            case TrustHandshakeState.Complete:
                _unsavedDeadlineMs = 0;
                _unsavedExpiredPending = false;
                _phase = PairPhase.Paired;
                ApplyPhaseUi();
                break;
            case TrustHandshakeState.TimedOut:
                _vm.SaveCardHint = TrustBindPolicy.AwaitingTimeoutReason;
                _vm.ShowSaveNameField = false;
                ApplyPhaseUi();
                break;
            case TrustHandshakeState.IncomingRequest req:
                _vm.SaveCardHint = $"{req.PeerAdvertisedName} wants to save this pairing.";
                _vm.ShowSaveNameField = true;
                ApplyPhaseUi();
                break;
            default:
                if (_skipSavePrompt)
                {
                    BeginUnsavedCap();
                    _phase = PairPhase.Paired;
                    ApplyPhaseUi();
                }
                break;
        }
    }

    private void OnXferState(PairingState state)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => OnXferState(state)); return; }
        switch (state)
        {
            case PairingState.Waiting:
                if (_checkingTrusted && _sendTarget is not null &&
                    _phase is PairPhase.Hub or PairPhase.Paired)
                {
                    _checkingTrusted = false;
                    _vm.CheckingTrusted = false;
                    _vm.Status = "";
                    _phase = PairPhase.Sending;
                    ApplyPhaseUi();
                }
                break;
            case PairingState.TrustedIncoming incoming:
                if (_checkingTrusted || _phase == PairPhase.Sending || _sendTarget is not null)
                {
                    break;
                }
                _incomingPeerName = incoming.PeerName;
                if (_live is not null) _ = _live.StopAsync();
                _phase = PairPhase.AcceptIncoming;
                _vm.Status = "";
                _vm.IncomingTitle = $"Incoming from {incoming.PeerName}";
                _vm.IncomingDetail = FileCountLabel(incoming.Files.Count);
                ApplyPhaseUi();
                break;
            case PairingState.Paired:
                if (_phase == PairPhase.Sending)
                {
                    if (_xfer is not null && !_xfer.IsTransferOrchestratorActive)
                        _ = _xfer.StartHostFileTransferAsync(_entries, _vm.EncryptEnabled);
                    ApplyPhaseUi();
                }
                else if (_phase is PairPhase.AcceptIncoming or PairPhase.Receiving)
                {
                    var shouldStart = _phase != PairPhase.Receiving;
                    _phase = PairPhase.Receiving;
                    ApplyPhaseUi();
                    if (shouldStart && _xfer is not null)
                    {
                        var expected = _xfer.RemoteFiles.ToList();
                        _ = _xfer.PrepareGuestFileSinkAsync(
                            _store.ReceiveFolder, expected, _vm.EncryptEnabled, beginTransfer: true);
                    }
                }
                break;
            case PairingState.Failed f:
                if (_checkingTrusted ||
                    _phase is PairPhase.Sending or PairPhase.Receiving or PairPhase.AcceptIncoming)
                {
                    _vm.Status = f.Reason;
                    _checkingTrusted = false;
                    _vm.CheckingTrusted = false;
                    if (_unsavedExpiredPending)
                        _ = RemintPairAsync(TrustBindPolicy.UnsavedExpiredReason);
                    else
                        _ = ReturnToHubAsync();
                }
                break;
        }
    }

    private void OnXferRemoteFiles(IReadOnlyList<SharedFileInfo> files)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => OnXferRemoteFiles(files)); return; }
        if (_phase == PairPhase.AcceptIncoming)
            _vm.IncomingDetail = FileCountLabel(files.Count);
    }

    private void OnXferProgress(TransferProgress? p)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => OnXferProgress(p)); return; }
        ApplyProgress(p);
    }

    private void OnXferComplete()
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(OnXferComplete); return; }
        _ = OnTransferEndedAsync(failed: null);
    }

    private void OnXferFailed(string reason)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => OnXferFailed(reason)); return; }
        _ = OnTransferEndedAsync(reason);
    }

    private void OnXferSavedFiles(IReadOnlyList<SavedFileRecord> files)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => OnXferSavedFiles(files)); return; }
        if (files.Count > 0 && _phase == PairPhase.ReceiveDone)
            ApplyReceiveResult(files);
    }

    private async Task OnTransferEndedAsync(string? failed)
    {
        if (_phase is not PairPhase.Sending and not PairPhase.Receiving) return;
        if (failed is not null)
        {
            _vm.Status = failed;
            _joiningTheirCode = false;
            _joinStartedAtMs = 0;
            TheirCodeBox.Text = "";
            _sendTarget = null;
            _entries = new();
            _phase = PairPhase.Hub;
            ApplyPhaseUi();
            if (_xfer is not null) await StopXferAsync();
            if (_live is not null) await _live.StopAsync();
            await RestartInboxAsync();
            await StartLiveHostAsync(newCode: true);
            return;
        }
        if (_phase == PairPhase.Sending)
        {
            _phase = PairPhase.SendDone;
            _vm.ResultKicker = "SENT";
            _vm.ResultTitle = _entries.Count == 1 ? "File sent" : "Files sent";
            _vm.ResultMessage = $"Finished sending {_entries.Count} item(s).";
            _vm.ResultOk = true;
            _vm.ResultFiles.Clear();
        }
        else
        {
            ApplyReceiveResult(_xfer?.SavedFiles ?? Array.Empty<SavedFileRecord>());
            PersistTrustIfComplete();
            _phase = PairPhase.ReceiveDone;
        }
        ApplyPhaseUi();
    }

    private void ApplyReceiveResult(IReadOnlyList<SavedFileRecord> files)
    {
        var downloaded = files.Count;
        _vm.ResultOk = downloaded > 0;
        _vm.ResultKicker = downloaded > 0 ? "RECEIVED" : "NOT RECEIVED";
        _vm.ResultTitle = downloaded switch
        {
            0 => "Nothing saved",
            1 => "File received",
            _ => "Files received"
        };
        _vm.ResultMessage = downloaded == 0
            ? "No files were saved on this device."
            : $"Saved {downloaded} file(s).";
        _vm.ResultFiles.Clear();
        foreach (var f in files)
        {
            _vm.ResultFiles.Add(new ResultFileRow(
                f.Name,
                FormatBytes(f.SizeBytes) + " · saved on device",
                f.LocalPath));
        }
    }

    private void ApplyProgress(TransferProgress? p)
    {
        if (p is null)
        {
            _vm.ProgressText = "";
            _vm.CurrentProgressText = "";
            return;
        }
        var pct = p.BytesTotal > 0 ? 100.0 * p.BytesDone / p.BytesTotal : 0;
        _vm.ProgressValue = pct;
        if (p.BytesTotal > 0 && p.BytesDone >= p.BytesTotal)
        {
            _vm.ProgressText =
                $"100% · {FormatBytes(p.BytesDone)} / {FormatBytes(p.BytesTotal)} · Waiting for the other device…";
        }
        else
        {
            var speed = p.SpeedBytesPerSec > 0 ? $"{FormatBytes(p.SpeedBytesPerSec)}/s" : "—";
            var eta = p.EtaSeconds is { } s
                ? (s < 60 ? $"{s}s left" : $"{s / 60}m {s % 60}s left")
                : "…";
            _vm.ProgressText =
                $"{pct:0}% · {FormatBytes(p.BytesDone)} / {FormatBytes(p.BytesTotal)} · {speed} · {eta}";
        }
        _vm.CurrentFileName = p.CurrentFileName ?? "Current file";
        var curPct = p.CurrentFileTotal > 0 ? 100.0 * p.CurrentFileDone / p.CurrentFileTotal : 0;
        _vm.CurrentProgressValue = curPct;
        _vm.CurrentProgressText = $"{FormatBytes(p.CurrentFileDone)} / {FormatBytes(p.CurrentFileTotal)}";
    }

    private void PersistTrustIfComplete()
    {
        if (_live?.TrustHandshake is not TrustHandshakeState.Complete complete) return;
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var label = TrustedDevices.SanitizeName(_pendingTrustLabel)
            ?? TrustedDevices.SanitizeName(complete.PeerAdvertisedName)
            ?? "Trusted device";
        _store.Add(new TrustedDevice(
            complete.PairId,
            complete.PeerDeviceId,
            label,
            complete.PeerAdvertisedName,
            complete.TrustKeyHex,
            now,
            now));
        RefreshDevices();
        _ = RestartInboxAsync();
    }

    private void SkipSaveAndPair()
    {
        if (_live?.TrustHandshake is TrustHandshakeState.TimedOut)
        {
            _ = RemintPairAsync();
            return;
        }
        _skipSavePrompt = true;
        _live?.DeclineTrustBind();
        BeginUnsavedCap();
        _phase = PairPhase.Paired;
        ApplyPhaseUi();
    }

    private void BeginUnsavedCap()
    {
        if (_live?.TrustHandshake is TrustHandshakeState.Complete)
        {
            _unsavedDeadlineMs = 0;
            _unsavedExpiredPending = false;
            return;
        }
        _unsavedDeadlineMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + TrustBindPolicy.UnsavedSessionMs;
        _unsavedExpiredPending = false;
    }

    private void OnTick()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        if (_joiningTheirCode && _joinStartedAtMs > 0 &&
            now - _joinStartedAtMs > 45_000 &&
            _live?.State is PairingState.Waiting or PairingState.Connecting or PairingState.Idle)
        {
            _joiningTheirCode = false;
            _joinStartedAtMs = 0;
            _vm.Status =
                "No response from the other device. Keep one device on its code screen; type that code on the other.";
            _ = CancelJoinAndRemintAsync();
            return;
        }

        var remaining = PairingCodeRotation.RemainingMs(_codeStartedAtMs, now);
        var freeze = !PairingCodeRotation.ShouldRotate(
            _live?.IsPeerJoined == true,
            _live?.State is PairingState.Confirming);
        if (!_joiningTheirCode && _phase is PairPhase.Hub && !freeze && remaining <= 0 &&
            PairPanel.Visibility == Visibility.Visible)
        {
            _ = StartLiveHostAsync(newCode: true);
        }
        else
        {
            _vm.CodeCountdown = _live?.IsPeerJoined == true
                ? "Code frozen until this pair finishes"
                : $"Refreshes in {FormatCountdown(remaining)}";
        }

        if (_unsavedDeadlineMs > 0 &&
            _phase is PairPhase.Paired or PairPhase.Sending or PairPhase.Receiving
                or PairPhase.AcceptIncoming or PairPhase.SendDone or PairPhase.ReceiveDone &&
            _live?.TrustHandshake is not TrustHandshakeState.Complete)
        {
            var left = Math.Max(0, _unsavedDeadlineMs - now);
            _vm.UnsavedCountdown = $"Unsaved pairing ends in {FormatCountdown(left)}";
            _vm.ShowUnsavedCountdown = true;
            if (left <= 0)
            {
                _unsavedDeadlineMs = 0;
                if (_phase is PairPhase.Sending or PairPhase.Receiving or PairPhase.AcceptIncoming
                    or PairPhase.SendDone or PairPhase.ReceiveDone)
                {
                    _unsavedExpiredPending = true;
                    _vm.Status = TrustBindPolicy.UnsavedExpiredReason;
                }
                else
                {
                    _ = RemintPairAsync(TrustBindPolicy.UnsavedExpiredReason);
                }
            }
        }
        else
        {
            _vm.ShowUnsavedCountdown = false;
        }
    }

    private void ApplyPhaseUi()
    {
        _vm.PairTitle = _phase == PairPhase.ConfirmPairing ? "Confirm pairing" : "Pair devices";
        _vm.ShowConfirmCard = _phase == PairPhase.Confirming;
        _vm.ShowSaveCard = _phase == PairPhase.ConfirmPairing;
        _vm.ShowSaveNameField = _phase == PairPhase.ConfirmPairing &&
                                _live?.TrustHandshake is not TrustHandshakeState.TimedOut;
        if (_phase == PairPhase.ConfirmPairing && _vm.SaveCardHint.Length == 0)
            _vm.SaveCardHint = "Save this device so you can send without a code next time.";
        _vm.ShowIncomingCard = _phase == PairPhase.AcceptIncoming;
        _vm.ShowTransfer = _phase is PairPhase.Sending or PairPhase.Receiving;
        _vm.ShowResult = _phase is PairPhase.SendDone or PairPhase.ReceiveDone;
        _vm.ShowHub = _phase is PairPhase.Hub or PairPhase.Paired;
        _vm.CheckingTrusted = _checkingTrusted;
        if (_phase == PairPhase.Sending)
        {
            var name = _sendTarget is { } d ? TrustedDevices.DisplayName(d) : "paired device";
            _vm.TransferHeadline = $"Sending to {name}";
            _vm.TransferSubhead = "Transfer started after the other device accepted.";
        }
        else if (_phase == PairPhase.Receiving)
        {
            _vm.TransferHeadline = $"Receiving from {_incomingPeerName}";
            _vm.TransferSubhead = $"Transfer started after you accepted {_incomingPeerName}.";
        }
        if (_phase == PairPhase.ConfirmPairing && string.IsNullOrWhiteSpace(_vm.SaveDeviceName))
            _vm.SaveDeviceName = _sessionPair is { } sp
                ? TrustedDevices.DisplayName(sp)
                : "";
        ApplyHubVisibility();
        ApplyResultColors();
    }

    private void ApplyHubVisibility()
    {
        var paired = _phase == PairPhase.Paired;
        var hub = _phase is PairPhase.Hub or PairPhase.Paired;
        // While joining, always show the pause banner (do not key off live State —
        // Idle/Connecting during Stop→StartGuest briefly hid both live code and pause).
        _vm.ShowLiveCode = hub && !_joiningTheirCode &&
            _live?.State is not PairingState.Paired and not PairingState.Confirming;
        _vm.ShowJoiningPause = hub && _joiningTheirCode;
        _vm.ShowPairedActions = paired;
        _vm.ShowJoinField = _phase == PairPhase.Hub;
        _vm.CanSend = !_checkingTrusted && _sessionPair is not null;
        _vm.ShowEmptyDevices = _vm.Devices.Count == 0;
        _vm.CodeDisplay = string.IsNullOrWhiteSpace(_liveCode)
            ? ""
            : PairingCode.FormatForDisplay(_liveCode);
    }

    private void ApplyResultColors()
    {
        if (_vm.ResultOk)
        {
            _vm.ResultBrush = new SolidColorBrush(Color.FromRgb(0xD2, 0xE3, 0xFC));
            _vm.ResultForeground = new SolidColorBrush(Color.FromRgb(0x17, 0x4E, 0xA6));
        }
        else
        {
            _vm.ResultBrush = new SolidColorBrush(Color.FromRgb(0xFC, 0xE8, 0xE6));
            _vm.ResultForeground = new SolidColorBrush(Color.FromRgb(0x5F, 0x21, 0x20));
        }
    }

    private void RefreshDevices()
    {
        _vm.Devices.Clear();
        foreach (var d in _store.List())
            _vm.Devices.Add(new DeviceRow(d));
        _vm.ShowEmptyDevices = _vm.Devices.Count == 0;
    }

    private static string AdvertisedName() =>
        TrustedDevices.AdvertisedName(Environment.MachineName, "Windows");

    private static string FileCountLabel(int n) =>
        n <= 0 ? "Incoming files" : $"{n} file(s) listed";

    private static string FormatCountdown(long remainingMs)
    {
        var totalSec = Math.Max(0, remainingMs / 1000);
        return $"{totalSec / 60}:{totalSec % 60:00}";
    }

    private static string FormatBytes(long n)
    {
        if (n < 1024) return $"{n} B";
        double v = n;
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var i = 0;
        while (v >= 1024 && i < units.Length - 1) { v /= 1024; i++; }
        return i <= 2 ? $"{v:0.0} {units[i]}" : $"{v:0.00} {units[i]}";
    }

    protected override async void OnClosed(EventArgs e)
    {
        _tick.Stop();
        if (_live is not null) await _live.StopAsync();
        await StopXferAsync();
        base.OnClosed(e);
    }
}

public sealed class DeviceRow
{
    public DeviceRow(TrustedDevice device) => Device = device;
    public TrustedDevice Device { get; }
    public string Name => TrustedDevices.DisplayName(Device);
}

public sealed record ResultFileRow(string Name, string Detail, string Path);

public sealed class InverseBoolToVisConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture) =>
        value is true ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture) =>
        throw new NotSupportedException();
}

public sealed class MainVm : INotifyPropertyChanged
{
    private static readonly Brush BlueContainer = new SolidColorBrush(Color.FromRgb(0xD2, 0xE3, 0xFC));
    private static readonly Brush BlueDark = new SolidColorBrush(Color.FromRgb(0x17, 0x4E, 0xA6));

    private string _status = "";
    private string _codeDisplay = "";
    private string _codeCountdown = "";
    private string _phrase = "";
    private string _confirmHint = "";
    private string _confirmButtonText = "Yes — words match";
    private string _pairTitle = "Pair devices";
    private string _saveCardHint = "";
    private string _saveDeviceName = "";
    private string _incomingTitle = "";
    private string _incomingDetail = "";
    private string _transferHeadline = "";
    private string _transferSubhead = "";
    private string _progressText = "";
    private string _currentFileName = "";
    private string _currentProgressText = "";
    private string _resultKicker = "";
    private string _resultTitle = "";
    private string _resultMessage = "";
    private string _unsavedCountdown = "";
    private string _renameValue = "";
    private string _aboutVersion = "";
    private double _progressValue;
    private double _currentProgressValue;
    private bool _canConfirm;
    private bool _canJoin;
    private bool _canSend = true;
    private bool _encryptEnabled;
    private bool _showConfirmCard;
    private bool _showSaveCard;
    private bool _showSaveNameField = true;
    private bool _showIncomingCard;
    private bool _showTransfer;
    private bool _showResult;
    private bool _showHub = true;
    private bool _showLiveCode = true;
    private bool _showJoiningPause;
    private bool _showPairedActions;
    private bool _showJoinField = true;
    private bool _showEmptyDevices = true;
    private bool _showUnsavedCountdown;
    private bool _showRename;
    private bool _checkingTrusted;
    private bool _resultOk = true;
    private Brush _resultBrush = BlueContainer;
    private Brush _resultForeground = BlueDark;

    public event PropertyChangedEventHandler? PropertyChanged;

    public string HomeSubtitle { get; } =
        "Pair with a short code. Direct when possible; otherwise an encrypted relay.";

    public ObservableCollection<DeviceRow> Devices { get; } = new();
    public ObservableCollection<ResultFileRow> ResultFiles { get; } = new();

    public string Status { get => _status; set => Set(ref _status, value); }
    public string CodeDisplay { get => _codeDisplay; set => Set(ref _codeDisplay, value); }
    public string CodeCountdown { get => _codeCountdown; set => Set(ref _codeCountdown, value); }
    public string Phrase { get => _phrase; set => Set(ref _phrase, value); }
    public string ConfirmHint { get => _confirmHint; set => Set(ref _confirmHint, value); }
    public string ConfirmButtonText { get => _confirmButtonText; set => Set(ref _confirmButtonText, value); }
    public string PairTitle { get => _pairTitle; set => Set(ref _pairTitle, value); }
    public string SaveCardHint { get => _saveCardHint; set => Set(ref _saveCardHint, value); }
    public string SaveDeviceName { get => _saveDeviceName; set => Set(ref _saveDeviceName, value); }
    public string IncomingTitle { get => _incomingTitle; set => Set(ref _incomingTitle, value); }
    public string IncomingDetail { get => _incomingDetail; set => Set(ref _incomingDetail, value); }
    public string TransferHeadline { get => _transferHeadline; set => Set(ref _transferHeadline, value); }
    public string TransferSubhead { get => _transferSubhead; set => Set(ref _transferSubhead, value); }
    public string ProgressText { get => _progressText; set => Set(ref _progressText, value); }
    public string CurrentFileName { get => _currentFileName; set => Set(ref _currentFileName, value); }
    public string CurrentProgressText { get => _currentProgressText; set => Set(ref _currentProgressText, value); }
    public string ResultKicker { get => _resultKicker; set => Set(ref _resultKicker, value); }
    public string ResultTitle { get => _resultTitle; set => Set(ref _resultTitle, value); }
    public string ResultMessage { get => _resultMessage; set => Set(ref _resultMessage, value); }
    public string UnsavedCountdown { get => _unsavedCountdown; set => Set(ref _unsavedCountdown, value); }
    public string RenameValue { get => _renameValue; set => Set(ref _renameValue, value); }
    public string AboutVersion { get => _aboutVersion; set => Set(ref _aboutVersion, value); }
    public double ProgressValue { get => _progressValue; set => Set(ref _progressValue, value); }
    public double CurrentProgressValue { get => _currentProgressValue; set => Set(ref _currentProgressValue, value); }
    public bool CanConfirm { get => _canConfirm; set => Set(ref _canConfirm, value); }
    public bool CanJoin { get => _canJoin; set => Set(ref _canJoin, value); }
    public bool CanSend { get => _canSend; set => Set(ref _canSend, value); }
    public bool EncryptEnabled { get => _encryptEnabled; set => Set(ref _encryptEnabled, value); }
    public bool ShowConfirmCard { get => _showConfirmCard; set => Set(ref _showConfirmCard, value); }
    public bool ShowSaveCard { get => _showSaveCard; set => Set(ref _showSaveCard, value); }
    public bool ShowSaveNameField { get => _showSaveNameField; set => Set(ref _showSaveNameField, value); }
    public bool ShowIncomingCard { get => _showIncomingCard; set => Set(ref _showIncomingCard, value); }
    public bool ShowTransfer { get => _showTransfer; set => Set(ref _showTransfer, value); }
    public bool ShowResult { get => _showResult; set => Set(ref _showResult, value); }
    public bool ShowHub { get => _showHub; set => Set(ref _showHub, value); }
    public bool ShowLiveCode { get => _showLiveCode; set => Set(ref _showLiveCode, value); }
    public bool ShowJoiningPause { get => _showJoiningPause; set => Set(ref _showJoiningPause, value); }
    public bool ShowPairedActions { get => _showPairedActions; set => Set(ref _showPairedActions, value); }
    public bool ShowJoinField { get => _showJoinField; set => Set(ref _showJoinField, value); }
    public bool ShowEmptyDevices { get => _showEmptyDevices; set => Set(ref _showEmptyDevices, value); }
    public bool ShowUnsavedCountdown { get => _showUnsavedCountdown; set => Set(ref _showUnsavedCountdown, value); }
    public bool ShowRename { get => _showRename; set => Set(ref _showRename, value); }
    public bool CheckingTrusted { get => _checkingTrusted; set => Set(ref _checkingTrusted, value); }
    public bool ResultOk { get => _resultOk; set => Set(ref _resultOk, value); }
    public Brush ResultBrush { get => _resultBrush; set => Set(ref _resultBrush, value); }
    public Brush ResultForeground { get => _resultForeground; set => Set(ref _resultForeground, value); }

    private void Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (Equals(field, value)) return;
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
