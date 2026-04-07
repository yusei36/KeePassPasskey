# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

PasskeyWin11 integrates KeePass as a native Windows 11 passkey provider. It has two components bridged by a named pipe:

```
Browser → Windows (webauthn.dll) → PasskeyProvider.exe (COM, -PluginActivated)
                                         ↓ Named pipe JSON (\\.\pipe\keepass-passkey-provider)
                                   KeePassPasskeyProvider.dll (loaded by KeePass.exe)
                                         ↓ KeePass Plugin API
                                   KeePass Database (KPEX_PASSKEY_* fields)
```

- **COM server** (`src/NativeComServer/`) — C++ EXE, MSIX-packaged, implements `IPluginAuthenticator`, acts as the pipe **client**
- **KeePass plugin** (`src/KeePassPlugin/`) — C# DLL, acts as the pipe **server**
- All crypto (EC P-256 keygen, ECDSA signing) lives in the C# plugin (`EcKeyHelper.cs`)
- The COM server handles Windows API surface only: CBOR decode/encode, Windows Hello UV, credential cache
- CLSID/AAGUID: `fdb141b2-5d84-443e-8a35-4698c205a502` (KeePassXC-compatible)
- Credentials stored as `KPEX_PASSKEY_*` fields (KeePassXC format)

## Build Commands

### Prerequisites
- Visual Studio 2022+ (toolset `v143`; use `v145` for VS 2026)
- Windows SDK 10.0.26100.7175+ (required for `webauthnplugin.h`)
- .NET Framework 4.8 SDK
- `KeePass.exe` placed in `build/` (not shipped): `copy "C:\Program Files\KeePass Password Safe 2\KeePass.exe" build\`

### Restore NuGet packages
NuGet restore is only needed for the C++ project (WIL headers via `packages.config`). The packages land in `packages/` at the repo root. Run once:
```
msbuild PasskeyWin11.sln /t:Restore
```
Or use `nuget restore PasskeyWin11.sln` if `nuget.exe` is on PATH.

### Build C# KeePass plugin
```
msbuild src\KeePassPlugin\KeePassPlugin.csproj /p:Configuration=Release /p:Platform=AnyCPU
```
Output: `build\Release\KeePassPasskeyProvider.dll`

### Build C++ COM server
The C++ project must be given `SolutionDir` explicitly when built outside the solution so it can resolve the `packages\` path for WIL headers:
```
msbuild src\NativeComServer\NativeComServer.vcxproj /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v145 /p:SolutionDir=E:\Repos\PasskeyWin11\
```
Output: `build\Release\PasskeyProvider.exe`

### Build MSIX package
```
msbuild src\NativeComServer.Package\NativeComServer.Package.wapproj /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v145 /p:SolutionDir=E:\Repos\PasskeyWin11\
```
Output: `src\NativeComServer.Package\AppPackages\NativeComServer.Package_1.0.0.0_x64_Test\NativeComServer.Package_1.0.0.0_x64.msix`

Note: `AppxPackageSigningEnabled` is `false` in the wapproj — the MSIX is unsigned and must be signed manually before install (see below).

## IPC Protocol

Messages are length-prefixed JSON: `[4-byte LE uint32 length][UTF-8 JSON]`

Request types: `ping`, `make_credential`, `get_assertion`, `get_credentials`

All binary fields (credentialId, clientDataHash, signatures, public key coordinates) are **base64url-encoded** strings. The `IpcProtocol.cs` file defines the full schema.

### Quick pipe test (PowerShell)
```powershell
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'keepass-passkey-provider', 'InOut')
$pipe.Connect(2000)
$request = '{"type":"ping","requestId":"test"}'
$bytes = [System.Text.Encoding]::UTF8.GetBytes($request)
$lenBytes = [System.BitConverter]::GetBytes([uint32]$bytes.Length)
$pipe.Write($lenBytes, 0, 4)
$pipe.Write($bytes, 0, $bytes.Length)
# Expected response: {"type":"ping","requestId":"test","status":"ready"}
```

## Deployment

### 1. Sign the MSIX (required — signing is disabled in the wapproj)

The package publisher in `Package.appxmanifest` is `CN=KeePassPasskeyProvider`. The signing cert subject must match exactly.

Create a self-signed cert (once per machine), sign the MSIX, and trust the cert. Run the signing step in a normal shell; the trust step requires an elevated shell:

```powershell
# Create cert (stores in CurrentUser\My)
$cert = New-SelfSignedCertificate -Type Custom -Subject 'CN=KeePassPasskeyProvider' `
    -KeyUsage DigitalSignature -FriendlyName 'PasskeyWin11 Test' `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}')
$thumb = $cert.Thumbprint

# Sign the MSIX (signtool.exe from Windows SDK)
& 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe' sign /fd SHA256 /sha1 $thumb `
    'src\NativeComServer.Package\AppPackages\NativeComServer.Package_1.0.0.0_x64_Test\NativeComServer.Package_1.0.0.0_x64.msix'
```

```powershell
# Trust the cert — run this block in an elevated (admin) PowerShell
$thumb = '<thumbprint from above>'
$cert = Get-ChildItem Cert:\CurrentUser\My\$thumb
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('TrustedPeople','LocalMachine')
$store.Open('ReadWrite')
$store.Add($cert)
$store.Close()
```

### 2. Install the MSIX

```powershell
Add-AppxPackage -Path 'src\NativeComServer.Package\AppPackages\NativeComServer.Package_1.0.0.0_x64_Test\NativeComServer.Package_1.0.0.0_x64.msix' -ForceUpdateFromAnyVersion
```

Verify: `Get-AppxPackage -Name '*KeePassPasskeyProvider*'`

### 3. Register provider and install plugin

```powershell
# Register COM server
PasskeyProvider.exe /register

# Install plugin DLL alongside KeePass.exe or in %APPDATA%\KeePass\Plugins\
```

Then enable in Windows Settings → Accounts → Passkeys → Advanced Options.

## Key Source Files

| File | Purpose |
|------|---------|
| `src/NativeComServer/PluginAuthenticator.cpp/.h` | `IPluginAuthenticator` implementation — entry point for all WebAuthn operations |
| `src/NativeComServer/PipeClient.cpp` | Named pipe client — sends JSON requests to KeePass plugin |
| `src/NativeComServer/CredentialCache.cpp` | In-memory credential cache for the COM server lifetime |
| `src/NativeComServer/SignatureVerifier.cpp` | Verifies request signatures from Windows |
| `src/NativeComServer/main.cpp` | COM server entry point, handles `-PluginActivated` flag |
| `src/KeePassPlugin/PasskeyProviderExt.cs` | KeePass plugin entry point |
| `src/KeePassPlugin/IPC/PipeServer.cs` | Named pipe server — listens and dispatches requests |
| `src/KeePassPlugin/IPC/RequestHandler.cs` | Handles `make_credential` / `get_assertion` logic |
| `src/KeePassPlugin/IPC/IpcProtocol.cs` | JSON message schema (request/response types) |
| `src/KeePassPlugin/Storage/PasskeyEntryStorage.cs` | KeePassXC-compatible `KPEX_PASSKEY_*` field storage |
| `src/KeePassPlugin/Passkey/EcKeyHelper.cs` | EC P-256 key generation and ECDSA signing |
| `src/KeePassPlugin/Passkey/AuthenticatorData.cs` | WebAuthn authenticatorData construction |
| `src/KeePassPlugin/Passkey/CborWriter.cs` | Minimal CBOR encoder for attestation objects |
| `src/NativeComServer.Package/Package.appxmanifest` | MSIX manifest — declares COM server and passkey provider |
