# keepassxc-protocol Passkey Compatibility Issue

## Summary

The keepassxc-protocol's passkey actions (`passkeys-get`, `passkeys-register`) are incompatible with Windows' Plugin Authenticator API due to differences in how `clientDataJSON` is handled.

## Background

### What is clientDataJSON?

In WebAuthn, `clientDataJSON` is a JSON structure containing:
```json
{
  "type": "webauthn.get" or "webauthn.create",
  "challenge": "<base64url-encoded challenge from server>",
  "origin": "https://example.com",
  "crossOrigin": false
}
```

The authenticator signs: `authenticatorData || SHA256(clientDataJSON)`

The relying party (website) verifies this signature using the `clientDataJSON` it receives back.

## The Two Flows

### Flow A: Browser Extension (keepassxc-protocol)

```
Website                Browser Extension              KeePassXC
   |                         |                           |
   |-- challenge ----------->|                           |
   |                         |-- challenge + origin ---->|
   |                         |                           |
   |                         |   KeePassXC builds:       |
   |                         |   clientDataJSON = {      |
   |                         |     type, challenge,      |
   |                         |     origin                |
   |                         |   }                       |
   |                         |   hash = SHA256(clientDataJSON)
   |                         |   signature = sign(authData || hash)
   |                         |                           |
   |                         |<-- signature + clientDataJSON
   |<-- signature + clientDataJSON                       |
   |                                                     |
   | (verifies using clientDataJSON it received)         |
```

**Key point:** KeePassXC builds `clientDataJSON` from the challenge and origin sent by the browser extension. It returns `clientDataJSON` so the browser can forward it to the website.

### Flow B: Windows Plugin Authenticator (current implementation)

```
Website                Browser/Windows               Plugin Provider        KeePass Plugin
   |                         |                           |                       |
   |-- challenge ----------->|                           |                       |
   |                         |                           |                       |
   |   Windows builds:       |                           |                       |
   |   clientDataJSON = {    |                           |                       |
   |     type, challenge,    |                           |                       |
   |     origin              |                           |                       |
   |   }                     |                           |                       |
   |   clientDataHash = SHA256(clientDataJSON)           |                       |
   |                         |                           |                       |
   |                         |-- clientDataHash -------->|                       |
   |                         |                           |-- clientDataHash ---->|
   |                         |                           |                       |
   |                         |                           |   sign(authData || clientDataHash)
   |                         |                           |                       |
   |                         |                           |<----- signature ------|
   |                         |<------ signature ---------|                       |
   |<-- signature + clientDataJSON (Windows has it)      |                       |
   |                                                     |                       |
   | (verifies using clientDataJSON Windows built)       |                       |
```

**Key point:** Windows builds `clientDataJSON` and computes the hash. The plugin only receives `clientDataHash` - it never sees the original challenge or origin. Windows already has `clientDataJSON` to return to the website.

## The Incompatibility

| Aspect | keepassxc-protocol | Windows Plugin API |
|--------|-------------------|-------------------|
| **Receives** | `challenge` + `origin` | `clientDataHash` (pre-computed) |
| **Builds** | `clientDataJSON` server-side | N/A - already built by Windows |
| **Returns** | `signature` + `clientDataJSON` | `signature` only (Windows has clientDataJSON) |

The keepassxc-protocol expects to receive `challenge` and `origin` so it can build `clientDataJSON`. But Windows' Plugin Authenticator API only provides the pre-computed `clientDataHash` (SHA256 of clientDataJSON). We cannot reverse a hash to get the original inputs.

## Why This Matters

- The standard `passkeys-get` and `passkeys-register` actions in keepassxc-protocol **will not work** with the Windows Plugin Authenticator
- KeePassXC's native passkey support is designed for browser extensions, not Windows platform integration
- Any Windows passkey provider using keepassxc-protocol would need custom extensions

## Possible Solutions

### Option 1: Extend keepassxc-protocol (Recommended)

Add new actions to KeePassNatMsg that accept `clientDataHash` directly:

```json
{
  "action": "passkeys-sign",
  "message": {
    "rpId": "example.com",
    "clientDataHash": "<base64-encoded hash>",
    "allowCredentials": [...]
  }
}
```

**Pros:**
- Clean separation of concerns
- Windows handles clientDataJSON, KeePass just signs
- Simpler plugin implementation (no clientDataJSON building)

**Cons:**
- Not compatible with stock KeePassXC (requires KeePassNatMsg modifications)
- Non-standard extension to the protocol

### Option 2: Keep Current Custom Protocol

Continue using the current custom IPC protocol which already handles `clientDataHash` correctly.

**Pros:**
- Already working
- No changes needed

**Cons:**
- Requires the separate KeePassPasskeyPlugin
- Not compatible with KeePassXC directly

## Recommendation

If the goal is to use KeePassNatMsg (which you control), **Option 1** is best. Add hash-based passkey actions to KeePassNatMsg alongside the existing challenge-based ones. The Windows provider uses the hash-based actions; browser extensions use the challenge-based ones.

If the goal is compatibility with stock KeePassXC, passkey operations via keepassxc-protocol are **not feasible** without upstream changes to KeePassXC itself.

---

# Credential Cache Sync Issue

## Summary

The keepassxc-protocol does not provide a way to list all stored passkeys, which prevents the Windows credential cache from being properly populated.

## Background

### Windows Credential Cache

Windows maintains an autofill cache for passkeys. When a user visits a website, Windows can show available passkeys in the credential picker UI **before** contacting the authenticator. This provides a better UX because:

1. User sees their available passkeys immediately
2. No need to unlock KeePass just to see if credentials exist
3. Faster credential selection

### Current Implementation

The current `CredentialCache.cs` implements this by:

```
1. Send "get_credentials" request to KeePass plugin (returns ALL passkeys)
2. Get current Windows cache via WebAuthNPluginAuthenticatorGetAllCredentials
3. Diff the two lists
4. Add new credentials via WebAuthNPluginAuthenticatorAddCredentials
5. Remove stale credentials via WebAuthNPluginAuthenticatorRemoveCredentials
```

This sync runs periodically and after each registration to keep Windows in sync with KeePass.

## The Problem

### keepassxc-protocol has no "list all passkeys" action

Available actions related to credentials:

| Action | Purpose | Limitation |
|--------|---------|------------|
| `get-logins` | Get credentials matching a URL | Requires URL parameter - can't list all |
| `passkeys-get` | Authenticate with a passkey | Requires rpId - can't list all |
| `passkeys-register` | Register a new passkey | Creates, doesn't list |

There is no `get-all-passkeys` or `list-passkeys` action in the protocol.

### Why get-logins doesn't work

The `get-logins` action searches by URL:
```json
{
  "action": "get-logins",
  "message": {
    "url": "https://example.com"
  }
}
```

Problems:
1. We'd need to know all possible URLs/rpIds in advance
2. Passkeys are stored with `rpId`, not full URLs
3. No wildcard or "list all" option

## Impact

Without credential cache sync:

| Feature | With Cache | Without Cache |
|---------|-----------|---------------|
| **Credential picker** | Shows passkeys immediately | Empty until KeePass responds |
| **User experience** | Instant feedback | Delayed, may seem broken |
| **KeePass locked** | Can still show cached list | No passkeys visible |
| **Multiple passkeys** | User can choose before auth | Must unlock KeePass first |

## Possible Solutions

### Option 1: Extend keepassxc-protocol

Add a new action to KeePassNatMsg:

```json
{
  "action": "get-all-passkeys",
  "message": {}
}
```

Response:
```json
{
  "credentials": [
    {
      "credentialId": "<base64url>",
      "rpId": "example.com",
      "userHandle": "<base64url>",
      "userName": "user@example.com",
      "displayName": "User Name"
    }
  ]
}
```

**Pros:** Full cache sync capability restored
**Cons:** Non-standard protocol extension

### Option 2: Track rpIds locally

Maintain a local list of known rpIds from:
- Previous registrations (we know the rpId)
- Previous authentications (we know the rpId)
- User configuration

Then query each rpId individually via `get-logins`.

**Pros:** Works with standard protocol
**Cons:** 
- Incomplete coverage (misses passkeys created elsewhere)
- Multiple round-trips
- Complex state management

### Option 3: Skip credential cache entirely

Accept that Windows autofill cache won't be populated.

**Pros:** No protocol changes needed
**Cons:** Degraded UX as described above

## Recommendation

If extending KeePassNatMsg (Option 1 from the clientDataHash issue), also add `get-all-passkeys`. This gives full functionality with your plugin while accepting that stock KeePassXC won't support these extensions.

If not extending the protocol, Option 3 (skip cache) is the pragmatic choice - the core passkey functionality still works, just with a less polished UX.

---

## References

- [keepassxc-protocol documentation](https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md)
- [WebAuthn Specification - clientDataJSON](https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson)
- Windows SDK: `webauthn.h` - `WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST.pbClientDataHash`
- Windows SDK: `webauthnplugin.h` - `WebAuthNPluginAuthenticatorAddCredentials`
