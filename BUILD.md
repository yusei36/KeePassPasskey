# Build Instructions

## Prerequisites

### C++ COM Server (PasskeyProvider.exe)
- Visual Studio 2022 **or newer** — VS 2022 uses toolset `v143`; if your version uses a different
  toolset, override at build time: `msbuild /p:PlatformToolset=v144` (or set it in the IDE)
- Windows SDK **10.0.26100.7175 or newer** (includes webauthn.h / webauthnplugin.h with plugin APIs)
- NuGet package: `Microsoft.Windows.ImplementationLibrary` (WIL)

### KeePass Plugin (KeePassPasskeyProvider.dll)
- .NET Framework 4.8 SDK
- KeePass 2.x — place `KeePass.exe` in `build/` (not shipped)
- NuGet: `Newtonsoft.Json 13.0.3`

### MSIX Packaging
- Visual Studio 2022 with "Windows Application Packaging" workload
- Developer certificate for signing (or use MSIX test signing)

---

## Build Steps

### 1. Restore NuGet packages

```
nuget restore PasskeyWin11.sln
```

Or use Visual Studio: right-click solution → Restore NuGet Packages.

### 2. Copy KeePass.exe to build/

```
copy "C:\Program Files\KeePass Password Safe 2\KeePass.exe" build\
```

### 3. Build the KeePass plugin

```
msbuild src\KeePassPlugin\KeePassPlugin.csproj /p:Configuration=Release /p:Platform=AnyCPU
```

Output: `build\Release\KeePassPasskeyProvider.dll`

### 4. Build the C++ COM server

```
msbuild src\NativeComServer\NativeComServer.vcxproj /p:Configuration=Release /p:Platform=x64
```

Output: `build\Release\PasskeyProvider.exe`

### 5. Build the MSIX package

Open `PasskeyWin11.sln` in Visual Studio 2022, select `NativeComServer.Package` as startup project, and build.

Or via CLI (requires signing setup):
```
msbuild src\NativeComServer.Package\NativeComServer.Package.wapproj /p:Configuration=Release /p:Platform=x64
```

---

## Deployment

### Install KeePass Plugin
Copy `KeePassPasskeyProvider.dll` to the KeePass plugins directory:
```
%APPDATA%\KeePass\Plugins\  (or wherever KeePass loads plugins from)
```
Or place it alongside `KeePass.exe`.

### Install MSIX Package
```
Add-AppxPackage -Path "path\to\NativeComServer.Package_1.0.0.0_x64.msix"
```

Or double-click the `.msix` file in Windows Explorer.

### Register the Passkey Provider
After installing the MSIX, run:
```
PasskeyProvider.exe /register
```

Then go to **Windows Settings → Accounts → Passkeys → Advanced Options** and enable the KeePass provider.

---

## Testing

### Test the KeePass plugin (standalone)
1. Start KeePass with the plugin loaded
2. Open a database
3. In PowerShell:
   ```powershell
   $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'keepass-passkey-provider', 'InOut')
   $pipe.Connect(2000)
   $request = '{"type":"ping","requestId":"test"}'
   $bytes = [System.Text.Encoding]::UTF8.GetBytes($request)
   $lenBytes = [System.BitConverter]::GetBytes([uint32]$bytes.Length)
   $pipe.Write($lenBytes, 0, 4)
   $pipe.Write($bytes, 0, $bytes.Length)
   # Read response...
   ```
   Expected: `{"type":"ping","requestId":"test","status":"ready"}`

### End-to-end test
1. Start KeePass, open a database
2. Navigate to https://webauthn.io in a browser
3. Register a passkey — Windows should prompt for Hello verification and create a KeePass entry
4. Verify the entry has `KPEX_PASSKEY_*` fields
5. Sign in — should succeed without creating a new entry

### KeePassXC compatibility
Open the KeePass database in KeePassXC and verify passkey entries are recognized by the browser extension.

---

## Architecture Notes

```
Browser → Windows (webauthn.dll) → PasskeyProvider.exe (COM, -PluginActivated)
                                         ↓ Named pipe JSON
                                   KeePassPasskeyProvider.dll (loaded by KeePass.exe)
                                         ↓ KeePass Plugin API
                                   KeePass Database (KPEX_PASSKEY_* fields)
```

- The COM server is the **pipe client** (connects per-operation)
- The KeePass plugin is the **pipe server** (listens on `\\.\pipe\keepass-passkey-provider`)
- All crypto (EC P-256 keygen, ECDSA signing) happens in the KeePass plugin
- The COM server handles Windows API surface only (CBOR decode/encode, Windows Hello UV)
