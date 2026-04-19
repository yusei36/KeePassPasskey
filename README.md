# KeePassPasskey

Use your KeePass database as a native Windows 11 passkey provider. Websites that support passkeys can create and use credentials stored in KeePass.

## How it works

Windows 11 routes passkey operations through a COM server registered as a plugin authenticator. This project implements that COM server and a KeePass plugin that handles the actual cryptography:

```
Browser → Windows (webauthn.dll) → KeePassPasskeyProvider.exe (COM, MSIX)
                                          ↓  Named pipe JSON
                                    KeePassPasskey.dll (KeePass plugin)
                                          ↓  KeePass Plugin API
                                    KeePass Database (KPEX_PASSKEY_* fields)
```

- **KeePassPasskeyProvider.exe** — COM server, MSIX-packaged, handles the Windows WebAuthn API surface (CBOR decode/encode, credential cache sync)
- **KeePassPasskey.dll** — KeePass plugin, handles EC P-256 key generation and ECDSA signing, stores credentials in the open database
- Credentials are stored in KeePassXC-compatible `KPEX_PASSKEY_*` fields, so they are readable by KeePassXC

## Requirements

- Windows 11 24H2 or later
- [KeePass 2.x](https://keepass.info/)
- .NET Framework 4.8 (included in Windows 11)

## Installation

### Option A — Release zip

1. Download `KeePassPasskey-<version>.zip` from the releases page and extract it.
2. Run `Install.bat` as Administrator — it trusts the included certificate and installs the MSIX.
3. Copy the `KeePassPasskeyPlugin` folder to your KeePass `Plugins` folder (e.g. `C:\Program Files\KeePass Password Safe 2\Plugins\`) and and (re)start KeePass.
4. In **KeePassPasskey** app click **Register** and then **Open Passkey Settings** to enable it.

### Option B — Build and install from source

See [Prerequisites](#Prerequisites) below, then run the install script:

```powershell
# Run as Administrator
.\scripts\Build-AndInstall.ps1
```

This builds the MSIX, creates a self-signed test certificate, trusts it, installs the package, and launches the provider UI.

In the provider UI, click **Register** to register the plugin with Windows, then click **Open Passkey Settings** to open **Settings → Accounts → Passkeys → Advanced Options** and enable **KeePassPasskey**.

#### Manual registration (CLI alternative)

```powershell
KeePassPasskeyProvider.exe /register
KeePassPasskeyProvider.exe /status   # verify
```

Then open Settings manually: **Settings → Accounts → Passkeys → Advanced Options** → enable **KeePassPasskey**.

## Building

### Prerequisites

| Requirement | Notes |
|---|---|
| Visual Studio 2026 | With .NET desktop development workload |
| Windows SDK 10.0.26100.7175+ | Required for `webauthnplugin.h` |
| .NET 10 SDK | For KeePassPasskeyProvider |
| .NET Framework 4.8 SDK | For KeePassPasskeyPlugin |
| KeePass.exe | Place at `build\KeePass\KeePass.exe` |

```powershell
# Copy KeePass.exe into the build tree (not shipped with this repo)
Copy-Item "C:\Program Files\KeePass Password Safe 2\KeePass.exe" build\KeePass\
```

## Credential storage

Passkeys are stored as standard KeePass entries using [KeePassXC's passkey field format](https://github.com/keepassxreboot/keepassxc):

| Field | Content |
|---|---|
| `KPEX_PASSKEY_CREDENTIAL_ID` | Base64url credential ID |
| `KPEX_PASSKEY_PRIVATE_KEY_PEM` | EC P-256 private key (PEM) |
| `KPEX_PASSKEY_RELYING_PARTY` | Relying party ID (e.g. `github.com`) |
| `KPEX_PASSKEY_USERNAME` | User name from registration |
| `KPEX_PASSKEY_USER_HANDLE` | Base64url user handle |
| `KPEX_PASSKEY_FLAG_BE` | Backup Eligibility flag — always `1` |
| `KPEX_PASSKEY_FLAG_BS` | Backup State flag — always `1` |

Credentials created here can be read by KeePassXC and vice versa.

`FLAG_BE` and `FLAG_BS` correspond to bits 3 and 4 of the WebAuthn authenticatorData flags byte. `BE=1` means the credential is eligible to be synced across devices; `BS=1` means it currently is. Both are set to `1` because a KeePass database is typically synced via cloud storage (Dropbox, OneDrive, etc.), making its passkeys genuine synced credentials. Relying parties use these flags to distinguish synced passkeys (`BE=1`) from hardware-bound keys such as a YubiKey (`BE=0`). This matches KeePassXC's behaviour.

## Security

- The KeePass plugin verifies the identity of the connecting COM server before processing any request. In production (MSIX-installed) it checks the package family name and that the executable is in the protected `WindowsApps` folder.
- All signing (ECDSA P-256) happens inside KeePass, so private keys are never sent over the pipe.

## Identifiers

| Identifier | Value |
|---|---|
| COM CLSID | `4bff0a65-fdd6-4f97-ac44-7741ecaa5d7e` |
| AAGUID | `9addb28c-b46f-4402-808f-019651441ff3` |

## Project structure

```
src/
  KeePassPasskey.Shared/        IPC protocol definitions, Base64URL helpers
  KeePassPasskeyProvider/       COM server (.NET 10, x64)
  KeePassPasskeyPlugin/         KeePass plugin (.NET Framework 4.8)
  KeePassPasskeyProvider.Package/  MSIX packaging (wapproj)
scripts/
  Build-AndInstall.ps1          Build, sign, and install for local testing (requires elevation)
  Publish-Package.ps1           Build Release, sign, and produce distributable zip
  Install.bat                   End-user installer (shipped inside the release zip)
  Shared.psm1                   Shared PowerShell module used by the scripts above
```
