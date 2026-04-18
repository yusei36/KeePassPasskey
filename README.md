# KeePassPasskey

Use your KeePass database as a native Windows 11 passkey provider. Websites that support passkeys can create and use credentials stored in KeePass.

## How it works

Windows 11 routes passkey operations through a COM server registered as a plugin authenticator. This project implements that COM server and a KeePass plugin that handles the actual cryptography:

```
Browser → Windows (webauthn.dll) → KeePassPasskeyProvider.exe (COM, MSIX)
                                          ↓  Named pipe JSON
                                    KeePassPasskeyPlugin.dll (KeePass plugin)
                                          ↓  KeePass Plugin API
                                    KeePass Database (KPEX_PASSKEY_* fields)
```

- **KeePassPasskeyProvider.exe** — COM server, MSIX-packaged, handles the Windows WebAuthn API surface (CBOR decode/encode, credential cache sync)
- **KeePassPasskeyPlugin.dll** — KeePass plugin, handles EC P-256 key generation and ECDSA signing, stores credentials in the open database
- Credentials are stored in KeePassXC-compatible `KPEX_PASSKEY_*` fields, so they are readable by KeePassXC

## Requirements

- Windows 11 (build 26100 or later)
- [KeePass 2.x](https://keepass.info/)
- .NET Framework 4.8 (included in Windows 11)

## Installation

### Option A — MSIX from release

1. Download `KeePassPasskeyProvider.Package_x64.msix` from the releases page.
2. Double-click the MSIX to install (you will be prompted to trust the certificate on first install).
3. Copy `KeePassPasskeyPlugin.dll` to your KeePass `Plugins` folder (e.g. `C:\Program Files\KeePass Password Safe 2\Plugins\`).
4. Restart KeePass.
5. Open **Settings → Accounts → Passkeys → Advanced Options** and select **KeePass Passkey Provider**.

### Option B — Build and install from source

See [Prerequisites](#Prerequisites) below, then run the install script:

```powershell
# Run as Administrator
.\scripts\sign-and-install.ps1
```

This builds the MSIX, creates a self-signed test certificate, trusts it, and installs the package.

After installation, open **Settings → Accounts → Passkeys → Advanced Options** and select **KeePass Passkey Provider**.

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
- The named pipe (`\\.\pipe\keepass-passkey-provider`) is only created when KeePass is running with an open database.

## Identifiers

| Identifier | Value |
|---|---|
| COM CLSID | `4bff0a65-fdd6-4f97-ac44-7741ecaa5d7e` |
| AAGUID | `fdb141b2-5d84-443e-8a35-4698c205a502` (KeePassXC-compatible) |

## Project structure

```
src/
  KeePassPasskey.Shared/        IPC protocol definitions, Base64URL helpers
  KeePassPasskeyProvider/       COM server (.NET 10, x64)
  KeePassPasskeyPlugin/         KeePass plugin (.NET Framework 4.8)
  KeePassPasskeyProvider.Package/  MSIX packaging (wapproj)
scripts/
  sign-and-install.ps1          Build, sign, and install for local testing
```
