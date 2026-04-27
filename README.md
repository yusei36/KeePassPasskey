# KeePassPasskey

A KeePass plugin that turns KeePass into a native Windows 11 passkey provider. Websites and apps that support passkeys work automatically — no browser extension required.

**[GitHub](https://github.com/yusei36/KeePassPasskey) · [Releases](https://github.com/yusei36/KeePassPasskey/releases)**

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

### Option A - automatic (recommended)

1. Download `KeePassPasskey-<version>.zip` from the [releases page](https://github.com/yusei36/KeePassPasskey/releases) and extract it.
2. Copy the `KeePassPasskeyPlugin` folder to your KeePass `Plugins` folder (e.g. `C:\Program Files\KeePass Password Safe 2\Plugins\`) and (re)start KeePass.
3. Run `Install.bat` as Administrator — it trusts the included certificate, installs the MSIX, and starts the **KeePassPasskey** provider app.
4. Click **Advanced Passkey Options** in the app and enable **KeePassPasskey**.
5. Both status indicators in the **KeePassPasskey** app should show green.

### Option B - manual

1. Download `KeePassPasskey-<version>.zip` from the [releases page](https://github.com/yusei36/KeePassPasskey/releases) and extract it.
2. Copy the `KeePassPasskeyPlugin` folder to your KeePass `Plugins` folder (e.g. `C:\Program Files\KeePass Password Safe 2\Plugins\`) and (re)start KeePass.
3. Trust the certificate: right-click `KeePassPasskey.cer` → **Install Certificate** → **Local Machine** → place it in the **Trusted People** store.
4. Install the MSIX: double-click `KeePassPasskeyProvider.Package_<version>_x64.msix` and click **Install**.
5. Launch **KeePassPasskey** from the Start menu, click **Advanced Passkey Options** in the app and enable **KeePassPasskey**.
6. Both status indicators in the **KeePassPasskey** app should show green.

### Option C - Build and install from source

See [Prerequisites](#Prerequisites) below, then:

1. Run the build script as Administrator — builds the MSIX, signs it, and launches the **KeePassPasskey** provider app:
   ```powershell
   .\scripts\Build-AndInstall.ps1 -Configuration Release
   ```
2. Copy the DLLs from `build\Release\` to a `KeePassPasskeyPlugin` folder inside your KeePass `Plugins` folder (e.g. `C:\Program Files\KeePass Password Safe 2\Plugins\KeePassPasskeyPlugin\`) and (re)start KeePass.
3. Click **Advanced Passkey Options** in the app and enable **KeePassPasskey**.
4. Both status indicators in the **KeePassPasskey** app should show green.

#### Manual registration (CLI alternative)

If auto-registration fails, you can register manually:

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
