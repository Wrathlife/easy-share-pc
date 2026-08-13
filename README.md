# Netshare for Windows

Native WPF client (self-contained `Netshare.exe`) that pairs with the Android app over MQTT signaling and transfers via WebRTC DataChannel or MQTT AES fallback.

- No ads, no accounts, no telemetry
- Share and Receive
- Protocol parity: see [`../docs/PROTOCOL.md`](../docs/PROTOCOL.md)

## Develop

```bat
dotnet build EasyShare.Desktop.sln
dotnet test tests\EasyShare.Protocol.Tests\EasyShare.Protocol.Tests.csproj
```

## Publish

```bat
publish.bat
```

Output: `artifacts\Netshare.exe`
