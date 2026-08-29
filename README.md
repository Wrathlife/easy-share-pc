# Netshare for Windows

Native WPF client (self-contained `Netshare.exe`) that pairs with the Android app over MQTT signaling and transfers via WebRTC DataChannel or MQTT AES fallback.

- No ads, no accounts, no telemetry
- Pair devices (live code + join), then send or receive
- Protocol parity with the Android Pair devices hub (trusted send after match-words)

## Develop

```bat
dotnet build EasyShare.Desktop.sln
dotnet test tests\EasyShare.Protocol.Tests\EasyShare.Protocol.Tests.csproj
```

## Publish

```bat
publish.bat
```

Output: `current\Netshare.exe` (stable launch path for the desktop shortcut). Raw publish files go to `artifacts\publish\`.
