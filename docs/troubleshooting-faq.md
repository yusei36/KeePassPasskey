# FAQ & Troubleshooting

For end-user instructions and UI walkthroughs, see the [User Guide](user-guide.md).

## Installation fails: the package is not compatible with the device

Error `0x80073CFD`, *"The package requires OS version 10.0.26100.0 or higher"*, means your Windows is too old. KeePassPasskey needs **Windows 11 24H2 or later** (any edition), because the Windows passkey plugin API it is built on does not exist in Windows 10 or Windows 11 23H2.

Check your version with `winver` (Win + R). On 23H2, upgrade to 24H2 or later; Windows Update does not always offer this feature update right away, and on a work PC your IT department may need to roll it out.

## Why is a TPM required?

The requirement comes from Windows, not from KeePassPasskey. When any third-party passkey provider is registered, Windows creates a hardware-backed signing key in the TPM and uses it to sign every passkey request it hands to the provider. This lets the provider confirm a request genuinely came from Windows and was approved by you, rather than being forged by other software on the PC. KeePassPasskey cannot opt out of this.

Creating that key needs a TPM that is present and enabled. When the TPM is unavailable, Windows cannot create the signing key, so KeePassPasskey fails to register as a passkey provider. As a result, it does not appear in the Windows **Advanced Passkey Options** and cannot be enabled there. Most often the TPM is simply disabled, so check your BIOS/firmware and enable it there. You can confirm the TPM's status in Windows by running `tpm.msc` (Win + R).

If the TPM is present and enabled but registration still fails, the question becomes whether the hardware itself is suitable. Windows 11 24H2 already requires a TPM 2.0 as a baseline, so almost all PCs have suitable hardware. Older TPMs are not automatically ruled out: the Windows component tries several key algorithms before giving up, and one user has reported KeePassPasskey working successfully on TPM 1.2. That does not guarantee it will work on every PC with TPM 1.2: registration may succeed, but you may still run into other TPM or Windows Hello issues afterwards, and a future Windows update could change which TPMs are accepted.

## Why is Windows Hello required?

For the same reason as the TPM: the signing key Windows creates for every third-party passkey provider is protected by Windows Hello. Without Windows Hello set up (a PIN, fingerprint or face), Windows refuses to register any third-party passkey provider, which shows up as error `0x80090029` ("not supported"). A TPM alone is not enough, and a Windows account password does not replace it.

Windows Hello also has to **stay** set up. It is not a one-time setup step: removing it takes KeePassPasskey, and every other third-party passkey provider, out of use.

Two things that may make this easier to live with:

- A Windows Hello PIN does not have to be a short number. Tick **Include letters and symbols** when you create it, and it can be a full passphrase.
- For daily use, KeePassPasskey can leave out the Windows Hello step and rely on its own confirmation prompt instead (see [Notifications & User Verification](user-guide.md#notifications--user-verification)). Be aware that this weakens the check: confirming a passkey operation is then a single click, but KeePassPasskey still tells the website that you were verified.

## I cannot set up a Windows Hello PIN

When **Settings → Accounts → Sign-in options** offers no way to add a PIN, or registration fails with `0x80090029` even though you tried to set one up:

- **Remote Desktop:** Windows does not offer PIN setup over a Remote Desktop session. Sign in at the PC itself, set up the PIN, then reconnect.
- **Hyper-V virtual machine:** Hyper-V's **Enhanced Session** is a Remote Desktop connection too. Switch to a basic session (**View →** untick **Enhanced Session**) and set up the PIN there. The VM also needs a virtual TPM: shut it down, open its **Settings → Security** and enable **Trusted Platform Module** (Generation 2 VMs only), then confirm with `tpm.msc` inside the VM.
- **Broken Windows Hello state:** if a PIN already exists, try [re-enrolling it](#re-enrolling-your-windows-hello-pin).

Afterwards click **Register** in the KeePassPasskey app again.

## The download or installer is flagged as malware

Microsoft Defender, SmartScreen, or your browser may flag the release `.zip` or the files inside the MSIX as a Trojan, with names such as `Trojan:Script/Wacatac.B!ml`, `Trojan:Win32/Tecabans.STV!cl`, or `Trojan:Win32/Wacatac.B!ml`. **These are false positives.** The `!ml` and `!cl` suffixes mean the verdict came from Microsoft's cloud machine-learning models ("this looks suspicious"), not from a signature match against known malware, and that kind of automated guess produces false positives far more often than a signature match.

What you can do, in order:

1. **Check whether it is already reported.** Search the [issues](https://github.com/yusei36/KeePassPasskey/issues) to see if the detection is already tracked (for example [issue #20](https://github.com/yusei36/KeePassPasskey/issues/20)). If it is not, please open a new issue with the exact detection name and version so it can be submitted to Microsoft as a false positive.
2. **Wait for Microsoft to clear it.** Once a false positive is reviewed, Microsoft removes the detection and the updated definitions roll out over time, so the flag usually disappears on its own. Update your definitions and retry: **Windows Security → Virus & threat protection → Check for updates**.
3. **Use the [Microsoft Store version](https://apps.microsoft.com/detail/9nwnfhjpspgz).** Store packages are signed and vetted by Microsoft, so they avoid these false positives entirely.
4. **Allow it manually:** only if you trust the source and need it before the detection clears:
   - If your browser blocked the download, download it again from the release page's direct link and choose **Keep** when prompted.
   - If Defender quarantined it, open **Windows Security → Virus & threat protection → Protection history**, select the detection, and choose **Actions → Allow** (then **Restore** if the file was removed).

## Smart App Control blocks KeePassPasskey.dll

With Smart App Control turned on, Windows may block the KeePass plugin when KeePass loads it, saying that part of the app was blocked.

This is a false positive, and it is cleared by submitting the plugin file to Microsoft. Please [open an issue](https://github.com/yusei36/KeePassPasskey/issues) (or comment on an existing one) with your KeePassPasskey version, so the plugin can be submitted. Once Microsoft has cleared it, the block goes away by itself with the next Defender definition update, usually within 24 hours. To get it sooner, use **Windows Security → Virus & threat protection → Check for updates**.

Smart App Control cannot be set to allow a single file, so waiting for the definition update is the way to go rather than turning Smart App Control off.

## KeePassPasskey does not appear in the provider list

- Open the KeePassPasskey app, go to **Advanced Passkey Options** (links to Windows Settings), and make sure **KeePassPasskey** is enabled.
- If it is not listed there at all, open the KeePassPasskey app and check the status indicators and the **Diagnostics** section for any error details. Try clicking **Unregister** followed by **Register** in the app, then check the log files for error messages if it still fails. The most common causes are a TPM that is not present or enabled (see [Why is a TPM required?](#why-is-a-tpm-required)), or Windows Hello being in a faulty state.
- Make sure a Windows Hello PIN is configured (see [Why is Windows Hello required?](#why-is-windows-hello-required) and [I cannot set up a Windows Hello PIN](#i-cannot-set-up-a-windows-hello-pin)). Sometimes [removing and re-adding the PIN](#re-enrolling-your-windows-hello-pin) resolves the issue.

## Re-enrolling your Windows Hello PIN

Windows Hello sometimes ends up in a broken state where it reports as unsupported even on hardware that fully supports it, often surfacing as the error code `0x80090029` ("not supported"). Removing and re-adding your PIN reinitialises the underlying credential store and sometimes fixes it.

1. Open **Settings** (Win + I).
2. Go to **Accounts → Sign-in options**.
3. Under **PIN (Windows Hello)**, click **Remove** and confirm with your account password.
4. Once removed, click **Set up** (or **Add**) under **PIN (Windows Hello)** again.
5. Enter your account password when prompted, then choose a new PIN.

After setting up the PIN again, try **Register** once more in the KeePassPasskey app.

## The KeePass plugin status indicator is not green

- Make sure KeePass is running with a database open.
- Check that the KeePassPasskey plugin is installed: in KeePass, go to **Tools → Plugins** and verify `KeePassPasskey` appears in the list.
- If the plugin is listed but the indicator is still red, restart KeePass.
- If it shows **Version mismatch** (yellow), the app and the KeePass plugin are on different but compatible versions. Passkeys keep working, but update the older side to get the latest features. The **Diagnostics** section shows both versions.
- If it shows **Incompatible version** (red), passkey operations are blocked until both sides are updated to matching versions. The app tells you which side is older.
- **When the plugin is the older side**, KeePass offers the update itself at its next start. You can also ask for it at any time with **Tools → KeePassPasskey → Update plugin from installed app** in KeePass, or with **Install plugin** in the KeePassPasskey app. The new plugin comes out of the installed app, so nothing is downloaded. See [Updates](user-guide.md#updates).
- **When the app is the older side**, update it: Microsoft Store installs update themselves in the background, and GitHub installs are updated by installing the newest release. KeePass then offers the matching plugin at its next start.

## I tried creating a passkey but it failed saying one already exists

- When you register, the website can ask the authenticator not to create a second passkey for an account that already has one in the same place. It sends the list of credential IDs it already knows for you, and if KeePass holds a matching one, KeePassPasskey declines to create a duplicate and the operation fails. This is expected behaviour: it stops you from accumulating multiple passkeys for the same account in the same authenticator.
- To register again, open the **Passkeys** group, delete the existing entry for that site, and retry. The website will then no longer recognise an existing passkey and will let you create a new one.
- Alternatively, if you deliberately keep more than one passkey for the same account (for example the same account in separate databases), relax the **Allow duplicate passkeys** setting in the KeePassPasskey app so the registration is not blocked. See [Settings](user-guide.md#settings).

## A site asks for enterprise attestation

- Some sites, usually workplace or government logins, ask for **enterprise attestation**: cryptographic proof of exactly which authenticator holds the passkey, so the site can insist on approved hardware. KeePassPasskey notes this in the creation dialog and creates the passkey without it.
- It cannot provide that proof, and this is by design rather than a gap. Attestation relies on a private key built into a security key or TPM during manufacture and signed by its vendor, which the authenticator can prove it holds but never reveal. KeePassPasskey is software, and your passkeys live in your KeePass database so you can back them up, sync them and move them between machines. There is nowhere to put such a key, and no honest claim to make about which device a passkey sits on. That portability is the reason to keep passkeys in KeePass, and it is exactly what enterprise attestation exists to rule out.
- Asking for it does not mean a site requires it, so the passkey may well be accepted anyway. If a site does refuse, you need a hardware security key for that site. No setting changes this.

## The website says there are no passkeys on this device

- Windows keeps its own copy of your passkeys so it can offer them in the sign-in prompt. When that copy is empty or out of date, Windows never asks KeePassPasskey for anything: you get no Windows Hello prompt, no confirmation prompt, and the browser reports that no passkey exists for the site.
- Check that **Sync passkeys to Windows** is on in **Settings → Advanced**. With it off, passkeys never reach the sign-in prompt at all.
- Make sure KeePass is running with your database open, then open the KeePassPasskey app, go to **Diagnostics** and click **Sync now**.
- If that does not help, click **Clear** and then **Sync now** to rebuild the copy from scratch.
- Older versions could get this copy permanently stuck when two entries held the same passkey, for example after duplicating an entry, after copying a passkey to another entry, or with the same database open twice. Once stuck, newly created passkeys never reached Windows, so sign-in kept failing even though registration still worked. Update to the latest version, then click **Sync now**.
- To report the problem, click **Write to log** in **Diagnostics** and attach the provider log. Usernames are not written to the log in full.

## Passkey prompts never show the Windows provider selection or KeePassPasskey

- A browser extension from another password manager (such as KeePassXC-Browser or any extension with passkey support) may be intercepting passkey requests before they reach Windows. When such an extension is active, the browser hands the passkey operation directly to that extension and Windows never gets involved, so KeePassPasskey is never called.
- Disable or remove any passkey-capable browser extensions and try again. If the Windows provider selection appears afterwards, the extension was the cause.

## Passkey creation fails without showing the KeePassPasskey dialog

- Make sure KeePass is running with a database. If the database is locked, KeePass comes to the front and asks you to unlock it first (see [When KeePass is locked](user-guide.md#when-keepass-is-locked)). If you cancel that, or no database was opened in KeePass at all, KeePassPasskey cannot save the passkey and fails before the dialog is shown. KeePass only needs to be open during the passkey operation itself.
- If a database is open and the problem persists, check the log files for error messages.

## How is the private key protected?

- The private key, the credential ID and the user handle are stored as protected fields with KeePass's in-memory protection turned on, the same protection a KeePass password field gets.
- To sign in, the plugin decrypts the private key inside the KeePass process only for the signature itself, and overwrites the decrypted copy right afterwards. Only the signature leaves KeePass. Copying or moving a passkey between entries never decrypts the key.
- Windows' copy of your passkeys holds only metadata (credential ID, site and user name), never the key.
- All of this happens inside KeePass, so KeePass Portable behaves exactly the same.

## Can I use my passkeys with KeePassXC?

Yes. Passkeys are stored in KeePassXC's own `KPEX_PASSKEY_*` fields and key format (see [Passkey entry format](user-guide.md#passkey-entry-format)), so KeePassXC, KeePassDX and other apps using that format can use passkeys created here, and the other way round. If KeePassPasskey ever stops working on your PC, you can open the same database in one of them and keep signing in without registering your passkeys again on each website.

## How do I uninstall KeePassPasskey completely?

See [Uninstalling](user-guide.md#uninstalling) in the User Guide.
