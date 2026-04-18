# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

KeePassPasskey integrates KeePass as a native Windows 11 passkey provider. It has two components bridged by a named pipe:

```
Browser → Windows (webauthn.dll) → KeePassPasskeyProvider.exe (COM, -PluginActivated)
                                         ↓ Named pipe JSON (\\.\pipe\keepass-passkey-provider)
                                   KeePassPasskeyPlugin.dll (loaded by KeePass.exe)
                                         ↓ KeePass Plugin API
                                   KeePass Database (KPEX_PASSKEY_* fields)
```

- **COM server** (`src/KeePassPasskeyProvider/`) — C# EXE, MSIX-packaged, implements `IPluginAuthenticator`, acts as the pipe **client**
- **KeePass plugin** (`src/KeePassPasskeyPlugin/`) — C# DLL, acts as the pipe **server**, verifies client process before accepting requests
- **Shared library** (`src/KeePassPasskey.Shared/`) — IPC protocol definitions, Base64URL encoding, AuthenticatorData construction, CBOR encoding
- All crypto (EC P-256 keygen, ECDSA signing) lives in the C# plugin (`EcKeyHelper.cs`)
- The COM server handles Windows API surface only: CBOR decode/encode, credential cache
- CLSID: `4bff0a65-fdd6-4f97-ac44-7741ecaa5d7e` (COM server identity, MSIX manifest + `KeePassPasskeyProviderClsid`)
- AAGUID: `9addb28c-b46f-4402-808f-019651441ff3` (defined once in `KeePassPasskeyProviderAaguid` in the provider)
- Credentials stored as `KPEX_PASSKEY_*` fields (KeePassXC format)

## IPC Protocol

Messages are length-prefixed JSON: `[4-byte LE uint32 length][UTF-8 JSON]`

Request types: `ping`, `make_credential`, `get_assertion`, `get_credentials`

All binary fields (credentialId, clientDataHash, signatures, public key coordinates) are **base64url-encoded** strings. The `IpcProtocol.cs` file defines the full schema.

### IPC Security

The plugin verifies connecting clients before processing requests (`ClientVerifier.cs`):

1. **MSIX-packaged apps**: Verifies package family name starts with `KeePassPasskeyProvider` and executable is in protected `WindowsApps` folder
2. **Standalone executables**: Verifies executable name and Authenticode signature

Verification is enabled by default in Release builds, disabled in Debug builds. Control via `ClientVerifier.Enabled`.

## Key Source Files

| File | Purpose |
|------|---------|
| `src/KeePassPasskeyProvider/Plugin/PluginAuthenticator.cs` | `IPluginAuthenticator` implementation — entry point for all WebAuthn operations |
| `src/KeePassPasskeyProvider/Plugin/CredentialCache.cs` | Syncs passkey credentials from KeePass to Windows autofill cache |
| `src/KeePassPasskeyProvider/Plugin/SignatureVerifier.cs` | Verifies request signatures from Windows |
| `src/KeePassPasskeyProvider/Ipc/PipeClient.cs` | Named pipe client — sends JSON requests to KeePass plugin |
| `src/KeePassPasskeyProvider/Program.cs` | COM server entry point, handles `-PluginActivated` flag |
| `src/KeePassPasskeyPlugin/KeePassPasskeyPluginExt.cs` | KeePass plugin entry point |
| `src/KeePassPasskeyPlugin/Ipc/PipeServer.cs` | Named pipe server — listens and dispatches requests |
| `src/KeePassPasskeyPlugin/Ipc/RequestHandler.cs` | Handles `make_credential` / `get_assertion` logic |
| `src/KeePassPasskeyPlugin/Ipc/ClientVerifier.cs` | Verifies connecting client is legitimate provider (MSIX or signed exe) |
| `src/KeePassPasskey.Shared/IpcProtocol.cs` | JSON message schema (request/response types) |
| `src/KeePassPasskey.Shared/Base64Url.cs` | Base64URL encoding/decoding |
| `src/KeePassPasskeyPlugin/Storage/PasskeyEntryStorage.cs` | KeePassXC-compatible `KPEX_PASSKEY_*` field storage |
| `src/KeePassPasskeyPlugin/Passkey/EcKeyHelper.cs` | EC P-256 key generation and ECDSA signing |
| `src/KeePassPasskey.Shared/AuthenticatorData.cs` | WebAuthn authenticatorData construction |
| `src/KeePassPasskey.Shared/CborWriter.cs` | Minimal CBOR encoder for attestation objects |
| `src/KeePassPasskeyProvider.Package/Package.appxmanifest` | MSIX manifest — declares COM server and passkey provider |
