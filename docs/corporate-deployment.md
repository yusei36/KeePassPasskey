# Using KeePassPasskey in a Corporate Environment

This guide is for IT administrators who want to roll out KeePassPasskey on managed Windows PCs, and for users who want to know what to ask their IT department for. For everyday use, see the [User Guide](user-guide.md); for individual problems, see [FAQ & Troubleshooting](troubleshooting-faq.md).

## Overview

KeePassPasskey consists of two parts, which are deployed separately:

| Part | What it is | Where it lives |
|---|---|---|
| **The app** (`KeePassPasskeyProvider.exe`) | An MSIX package that Windows activates as a passkey provider. It also hosts the KeePassPasskey app window | Installed per user by Windows, like any MSIX app |
| **The plugin** (`KeePassPasskey.dll`) | A KeePass plugin that creates and stores the passkeys and signs with them | KeePass's `Plugins` folder |

Both must be present, and both must be on compatible versions (see [Keeping the app and plugin versions matched](#keeping-the-app-and-plugin-versions-matched)).

Passkeys are stored in the KeePass database (KDBX) as ordinary entries. Nothing is stored in the cloud, and neither part makes network connections of its own. The only data that leaves KeePass is passkey metadata (credential ID, site and user name, never the private key) written to the Windows credential cache so Windows can offer the passkeys in its sign-in dialogs.

## Prerequisites

Check these on your client baseline before anything else, because none of them can be worked around by KeePassPasskey:

| Requirement | Notes |
|---|---|
| Windows 11 24H2 or later | The Windows passkey plugin API does not exist in earlier versions. Installation fails with `0x80073CFD` otherwise |
| TPM enabled | Windows creates a TPM-backed key for every third-party passkey provider. See [Why is a TPM required?](troubleshooting-faq.md#why-is-a-tpm-required) |
| Windows Hello set up for the user | At least a PIN. Windows refuses to register any third-party passkey provider without it (`0x80090029`). See [Why is Windows Hello required?](troubleshooting-faq.md#why-is-windows-hello-required) |
| KeePass 2.54 or later | Installed or portable |

Things to look out for in managed environments:

- **Windows Hello policies.** If Windows Hello or Windows Hello for Business is disabled by Group Policy or Intune, users cannot set up a PIN and KeePassPasskey cannot register. Windows Hello for Business is fine; the regular Windows Hello PIN is enough as well.
- **Remote Desktop and VDI.** Windows does not offer PIN setup over a Remote Desktop session. Virtual machines need a virtual TPM. See [I cannot set up a Windows Hello PIN](troubleshooting-faq.md#i-cannot-set-up-a-windows-hello-pin).
- **Feature update rollout.** If your organisation holds back feature updates, PCs may still be on 23H2.

## Choosing a distribution channel

KeePassPasskey is published through two channels with identical functionality:

| | Microsoft Store | GitHub release |
|---|---|---|
| Package family name | `51133UweKgel.KeePassPasskey_2xyhjw5z6d8g4` | `KeePassPasskeyProvider_rcm79ea08mqe4` |
| Signing | Signed by Microsoft | Signed with the project's own certificate, which must be trusted on the PC |
| App updates | Automatic through the Store | You deploy each new version yourself |
| Version control | Follows the Store | Fully under your control |

**Pick one channel per PC.** Both can be installed side by side, but then users see two KeePassPasskey entries in Windows and the plugin talks to whichever it prefers. Mixing them only makes support harder.

As a rule of thumb: use the **Store** channel if your PCs can reach the Microsoft Store (directly or through Intune), and the **GitHub** channel if the Store is blocked or you need to pin a version.

## Deploying the app

### Microsoft Store channel

- **Intune:** add the app as a **Microsoft Store app (new)** and search for *KeePassPasskey*, or use Store ID `9NWNFHJPSPGZ`.
- **winget** (for scripts or other management tools):

  ```powershell
  winget install 9NWNFHJPSPGZ --source msstore --accept-package-agreements --accept-source-agreements
  ```

The Store keeps the app up to date by itself. Read [Keeping the app and plugin versions matched](#keeping-the-app-and-plugin-versions-matched) before relying on that.

### GitHub channel

Download `KeePassPasskey-<version>.zip` from the [releases page](https://github.com/yusei36/KeePassPasskey/releases). It contains the MSIX package, the certificate (`KeePassPasskey.cer`) and the plugin.

**1. Trust the certificate.** Deploy `KeePassPasskey.cer` to the **Local Machine → Trusted People** store, through Group Policy (*Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies → Trusted People*), an Intune trusted certificate profile, or:

```powershell
certutil -addstore TrustedPeople KeePassPasskey.cer
```

Keep the certificate deployed for as long as the package is provisioned, so that the app can be registered for users who sign in for the first time later.

**2. Install the package.** Either provision it for every user of the PC (run elevated):

```powershell
Add-AppxProvisionedPackage -Online -PackagePath KeePassPasskeyProvider.Package_<version>_x64.msix -SkipLicense
```

or install it for the current user only (run as that user, not elevated):

```powershell
Add-AppxPackage -Path KeePassPasskeyProvider.Package_<version>_x64.msix
```

Sideloading must be allowed, which is the default on Windows 11 unless a policy turns it off (*Allow all trusted apps to install*).

The `InstallMsix.bat` script from the release zip is meant for interactive installs on a single PC. It installs for the signed-in user through a scheduled task, so do not use it from a deployment tool that runs as SYSTEM.

**3. Updates.** Deploy each new release the same way. A newer version installs over the old one and keeps the users' settings.

## Deploying the plugin

Copy `KeePassPasskey.dll` into KeePass's `Plugins` folder, for example `C:\Program Files\KeePass Password Safe 2\Plugins\`. KeePass loads it at its next start.

The DLL is in the GitHub release zip. It also ships inside the app package, in its `KeePassPasskeyPlugin\` folder, so the plugin always matches the app installed on the PC:

```powershell
$pkg = Get-AppxPackage -AllUsers -Name '*KeePassPasskey*' | Select-Object -First 1
Copy-Item (Join-Path $pkg.InstallLocation 'KeePassPasskeyPlugin\KeePassPasskey.dll') `
	'C:\Program Files\KeePass Password Safe 2\Plugins\' -Force
```

Close KeePass before overwriting the file, or the copy fails because KeePass has it loaded.

For KeePass Portable or per-user installations, users can install the plugin themselves from the app (**Install plugin**) without administrator rights.

### Application control

The plugin DLL is not code-signed. If you use **AppLocker** DLL rules or **App Control for Business** (WDAC), allow `KeePassPasskey.dll` by path or by file hash. The hash changes with every release.

**Smart App Control** may block the plugin until Microsoft has cleared a new release, see [Smart App Control blocks KeePassPasskey.dll](troubleshooting-faq.md#smart-app-control-blocks-keepasspasskeydll). Smart App Control is usually off on managed PCs.

## Keeping the app and plugin versions matched

The app and the plugin check each other's protocol version on every request:

- **Version mismatch** (yellow): different but compatible versions. Passkeys keep working.
- **Incompatible version** (red): passkey operations are blocked until the older side is updated.

Most releases are compatible with the previous ones, but plan for the case where they are not:

- **Users without administrator rights cannot update a plugin under `C:\Program Files\`.** KeePass offers the update from the installed app at its next start, but writing to `Program Files` needs elevation. Without it the user sees an administrator prompt they cannot complete.
- **Store installs update the app on their own**, while the plugin only changes when someone copies it. Over time the app gets ahead of the plugin.

The simplest setup is to **deploy the app and the plugin together** in the same job, with the plugin copied from the installed package as shown above, and to rerun that job whenever the app changes. With the Store channel, an Intune remediation script or a scheduled task that compares the two versions and copies the DLL works well. If that is not practical, the GitHub channel gives you full control over when the app version changes.

When IT owns plugin updates, turn off the in-KeePass update prompt so users are not asked to do something they cannot do (`checkForPluginUpdates`, see below).

## Enabling the provider for each user

Two steps are per user and happen on the PC itself:

1. **Registration with Windows.** Happens automatically the first time the user opens the KeePassPasskey app, or the first time KeePass opens a database with the plugin loaded. No administrator rights are needed.
2. **Turning the provider on.** The user switches on **KeePassPasskey** under **Settings → Accounts → Passkeys → Advanced options**. The app's Setup Guide links straight to that page. Windows keeps this switch per user, and it stays on across app updates.

Both status indicators in the KeePassPasskey app then show green. To check this from a script, run `KeePassPasskeyProvider.exe /status` as the user, see [Command-line options](#command-line-options).

## Preconfiguring settings

The KeePassPasskey settings are stored by the plugin in KeePass's configuration, as a single JSON value under the key `KeePassPasskey.Settings`. That means you can preset them with KeePass's own configuration mechanisms, the same way as other KeePass settings.

To **enforce** settings, add them to `KeePass.config.enforced.xml` next to `KeePass.exe` (see [Enforced Configuration](https://keepass.info/help/kb/config_enf.html) in the KeePass documentation):

```xml
<?xml version="1.0" encoding="utf-8"?>
<Configuration xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
	<Custom>
		<Item>
			<Key>KeePassPasskey.Settings</Key>
			<Value>{"registrationVerification":3,"signInVerification":3,"checkForPluginUpdates":false}</Value>
		</Item>
	</Custom>
</Configuration>
```

Keep in mind:

- **The value is all or nothing.** It holds every KeePassPasskey setting at once, so enforcing it locks all of them. Settings left out of the JSON fall back to their defaults, with one exception: the Spoof AAGUID option is turned off unless the JSON sets `"allowAaguidSpoofing":true`.
- **Users cannot change them in the app.** The app's Settings page shows a **Settings enforced by KeePass** notice and greys out every setting stored in KeePass. A change saved by other means, such as an older version of the app, is stored in the user's configuration but not applied: KeePassPasskey keeps using the enforced values.
- The JSON must be valid and XML-escaped where needed (`&`, `<`).
- **Users must not be able to write to the KeePass folder**, or they can simply edit the enforced file. That rules out enforcing settings for KeePass Portable in a user-writable location.

The settings you are most likely to care about:

| JSON key | Default | Values | Why it matters |
|---|---|---|---|
| `registrationVerification`, `signInVerification` | `3` | `3` both, `1` Windows Hello only, `2` confirmation prompt only, `0` none | How the user is verified when creating or using a passkey. With `2` or `0` the user is no longer verified by Windows Hello, but KeePassPasskey still reports the user as verified to the website. Keep `3` or `1` unless you have a reason not to |
| `skipWindowsHelloAfterUnlock` | `false` | `true`, `false` | Skips Windows Hello when the user has just unlocked KeePass for the same request |
| `checkForPluginUpdates` | `true` | `true`, `false` | Set to `false` when IT deploys plugin updates |
| `syncCredentialsToWindows` | `true` | `true`, `false` | Leave on. Without it, passkeys do not appear in the Windows sign-in prompt |
| `newPasskeyBackupEligible`, `newPasskeyBackupState` | `true` | `true`, `false` | The backup flags written to new passkeys, see [Backup flags](#backup-flags-and-attestation) |
| `logLevel` | `Info` | `Off`, `Error`, `Warn`, `Info`, `Debug` | Log verbosity |
| `notificationVerificationTimeoutMilliseconds` | `60000` | number | How long the confirmation prompt waits |
| `allowAaguidSpoofing` | `false` when enforced, otherwise `true` | `true`, `false` | `false` removes the [Spoof AAGUID](user-guide.md#spoof-aaguid) option, so new passkeys always report KeePassPasskey's own AAGUID. A value a user already applied is reset to the default the next time KeePass opens or saves a database. This setting has no control in the app and can only be set in the configuration file. Enforcing the settings turns it off unless the enforced JSON sets it to `true` |

The full list of settings is described in [Settings](user-guide.md#settings) in the User Guide.

Settings that belong to the app window only (theme, tray icon) are stored per user in the app's own storage and cannot be preset this way.

## Security considerations

Questions security teams usually ask, with short answers:

**Where are the private keys?** In the KeePass database, protected by the database's master key and, while KeePass runs, by KeePass's in-memory protection. Signing happens inside the KeePass process; the key is never sent to the app or to Windows. See [How is the private key protected?](troubleshooting-faq.md#how-is-the-private-key-protected) Back up and protect the database according to your existing KeePass policy.

**Who can talk to the plugin?** Only the official KeePassPasskey package (checked by package family name), running as the same user at medium integrity. Other users on the same PC, including with fast user switching, each get their own connection.

**Can passkeys leave the PC?** Yes, together with the database. That is by design: passkeys in KeePass are portable, can be backed up, and can be opened with other compatible KDBX software like KeePassXC. If your policy requires device-bound passkeys, KeePassPasskey is not the right authenticator for those accounts.

### Backup flags and attestation

Relying parties, including your own identity provider, may look at two properties of a passkey:

- **Backup flags (BE/BS).** By default, KeePassPasskey marks new passkeys as backed up (synced), which is accurate for a passkey stored in a database file. Some services accept only device-bound passkeys. You can change the default for new passkeys (`newPasskeyBackupEligible`, `newPasskeyBackupState`), but marking a portable passkey as device-bound is a claim KeePassPasskey cannot back up.
- **Attestation.** KeePassPasskey creates passkeys without attestation, since a software authenticator has no manufacturer-signed key to prove its identity with. Services that **enforce** attestation, as identity providers such as Microsoft Entra ID can be configured to, will reject KeePassPasskey passkeys. See [A site asks for enterprise attestation](troubleshooting-faq.md#a-site-asks-for-enterprise-attestation).

If your identity provider restricts passkeys by authenticator model (AAGUID), KeePassPasskey's AAGUID is:

`9addb28c-b46f-4402-808f-019651441ff3`

Whether to allow it there is a policy decision: an AAGUID is a claim by the authenticator, not proof, so allowing it means allowing passkeys that can be copied with the database.

## Other things that interfere

- **Browser extensions** of other password managers can intercept passkey requests before they reach Windows. If you deploy such an extension by policy, KeePassPasskey is never called in that browser. See [Passkey prompts never show the Windows provider selection](troubleshooting-faq.md#passkey-prompts-never-show-the-windows-provider-selection-or-keepasspasskey).
- **Other passkey providers** can be enabled at the same time. Windows asks the user which one to use.
- **Focus Assist / Do Not Disturb** only matters if the legacy notification prompts are turned on; the default dialog prompts are not affected.

## Removing KeePassPasskey

1. Remove the app:

   ```powershell
   # Stop provisioning it for new users (GitHub channel or provisioned installs)
   Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like '*KeePassPasskey*' | Remove-AppxProvisionedPackage -Online
   # Remove it for all existing users
   Get-AppxPackage -AllUsers -Name '*KeePassPasskey*' | Remove-AppxPackage -AllUsers
   ```

   For Store installs deployed through Intune, use an uninstall assignment instead. Windows removes KeePassPasskey as a passkey provider together with the app.
2. Delete `KeePassPasskey.dll` from the KeePass `Plugins` folder while KeePass is closed.
3. For the GitHub channel, remove the certificate from **Trusted People** once no PC needs it any more.
4. Optionally remove the `KeePassPasskey.*` entries from KeePass's configuration and the plugin log folder `%LOCALAPPDATA%\KeePassPasskey`.

The users' passkeys stay in their databases as ordinary entries.

## Troubleshooting for administrators

| What | Where |
|---|---|
| Plugin log | `%LOCALAPPDATA%\KeePassPasskey\Plugin.log` |
| App log | `%LOCALAPPDATA%\Packages\<package family name>\LocalCache\Provider.log` |
| App and plugin versions, registration state | The **Diagnostics** page of the KeePassPasskey app |

The **Diagnostics** page also shows both logs live and can write the state of the Windows credential cache to the log, which is the most useful thing to attach to a support ticket. Usernames are not written to the log in full.

### Command-line options

The app installs the command `KeePassPasskeyProvider.exe` for every user it is installed for, so it can be run from any command prompt or PowerShell window without a path. The same actions are available as buttons on the app's **Diagnostics** page.

| Command | What it does |
|---|---|
| `KeePassPasskeyProvider.exe /status` | Prints whether KeePassPasskey is `Enabled` or `Disabled` in **Settings → Accounts → Passkeys → Advanced options**. Fails if it is not registered with Windows at all |
| `KeePassPasskeyProvider.exe /register` | Registers KeePassPasskey as a passkey provider with Windows. Normally happens automatically; use it if the provider is missing from the Windows settings page |
| `KeePassPasskeyProvider.exe /unregister` | Removes the registration with Windows. Run `/register` afterwards to add it again |
| `KeePassPasskeyProvider.exe /synccredential` | Refreshes the Windows credential cache from the databases open in KeePass, like **Sync now**. KeePass runs this itself whenever a database is opened, saved or closed |
| `KeePassPasskeyProvider.exe /dumpcredentials` | Lists the passkeys in the Windows credential cache next to the passkeys KeePass currently has open, to spot entries that are missing or stale. KeePass must be running with the database open for the KeePass side |
| `KeePassPasskeyProvider.exe /clearcredentials` | Empties the Windows credential cache. It is filled again the next time KeePass opens or saves a database |
| `KeePassPasskeyProvider.exe /settings` | Opens the app on its Settings page |
| `KeePassPasskeyProvider.exe` | Opens the app |

The commands return exit code `0` on success and `1` on failure, so they can be used in scripts such as Intune remediations.

Everything here is per user: registration, the provider switch and the credential cache all belong to the signed-in user. Run the commands **as that user and not elevated**. From a tool that runs as SYSTEM, or as an administrator account, they report on that account, not on the user.

For specific error messages, see [FAQ & Troubleshooting](troubleshooting-faq.md).
