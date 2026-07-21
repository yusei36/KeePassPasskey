# FAQ & Troubleshooting

For end-user instructions and UI walkthroughs, see the [User Guide](user-guide.md).

## Why is a TPM required?

The requirement comes from Windows, not from KeePassPasskey. When any third-party passkey provider is registered, Windows creates a hardware-backed signing key in the TPM and uses it to sign every passkey request it hands to the provider. This lets the provider confirm a request genuinely came from Windows and was approved by you, rather than being forged by other software on the PC. KeePassPasskey cannot opt out of this.

Creating that key needs a TPM that is present and enabled. When the TPM is unavailable, Windows cannot create the signing key, so KeePassPasskey fails to register as a passkey provider. As a result, it does not appear in the Windows **Advanced Passkey Options** and cannot be enabled there. Most often the TPM is simply disabled, so check your BIOS/firmware and enable it there. You can confirm the TPM's status in Windows by running `tpm.msc` (Win + R).

If the TPM is present and enabled but registration still fails, the question becomes whether the hardware itself is suitable. Windows 11 24H2 already requires a TPM 2.0 as a baseline, so almost all PCs have suitable hardware. Older TPMs are not automatically ruled out: the Windows component tries several key algorithms before giving up, and one user has reported KeePassPasskey working successfully on TPM 1.2. That does not guarantee it will work on every PC with TPM 1.2: registration may succeed, but you may still run into other TPM or Windows Hello issues afterwards, and a future Windows update could change which TPMs are accepted.

## The download or installer is flagged as malware

Microsoft Defender, SmartScreen, or your browser may flag the release `.zip` or the files inside the MSIX as a Trojan, with names such as `Trojan:Script/Wacatac.B!ml`, `Trojan:Win32/Tecabans.STV!cl`, or `Trojan:Win32/Wacatac.B!ml`. **These are false positives.** The `!ml` and `!cl` suffixes mean the verdict came from Microsoft's cloud machine-learning models ("this looks suspicious"), not from a signature match against known malware, and that kind of automated guess produces false positives far more often than a signature match.

What you can do, in order:

1. **Check whether it is already reported.** Search the [issues](https://github.com/yusei36/KeePassPasskey/issues) to see if the detection is already tracked (for example [issue #20](https://github.com/yusei36/KeePassPasskey/issues/20)). If it is not, please open a new issue with the exact detection name and version so it can be submitted to Microsoft as a false positive.
2. **Wait for Microsoft to clear it.** Once a false positive is reviewed, Microsoft removes the detection and the updated definitions roll out over time, so the flag usually disappears on its own. Update your definitions and retry: **Windows Security → Virus & threat protection → Check for updates**.
3. **Use the [Microsoft Store version](https://apps.microsoft.com/detail/9nwnfhjpspgz).** Store packages are signed and vetted by Microsoft, so they avoid these false positives entirely.
4. **Allow it manually:** only if you trust the source and need it before the detection clears:
   - If your browser blocked the download, download it again from the release page's direct link and choose **Keep** when prompted.
   - If Defender quarantined it, open **Windows Security → Virus & threat protection → Protection history**, select the detection, and choose **Actions → Allow** (then **Restore** if the file was removed).

## KeePassPasskey does not appear in the provider list

- Open the KeePassPasskey app, go to **Advanced Passkey Options** (links to Windows Settings), and make sure **KeePassPasskey** is enabled.
- If it is not listed there at all, open the KeePassPasskey app and check the status indicators and the **Diagnostics** section for any error details. Try clicking **Unregister** followed by **Register** in the app, then check the log files for error messages if it still fails. The most common causes are a TPM that is not present or enabled (see [Why is a TPM required?](#why-is-a-tpm-required)), or Windows Hello being in a faulty state.
- Make sure Windows Hello PIN is configured. Sometimes [removing and re-adding the PIN](#re-enrolling-your-windows-hello-pin) resolves the issue.

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
- If it shows **Version mismatch** (yellow), the app and the KeePass plugin are on different but compatible versions. Passkeys keep working, but update the older side to get the latest features. The **Diagnostics** section shows both versions and, when the plugin is the older one, offers to reveal the bundled plugin file so you can drop it into your KeePass plugins folder.
- If it shows **Incompatible version** (red), passkey operations are blocked until both sides are updated to matching versions. The app tells you which side is older: update that one by replacing the plugin file in your KeePass plugins folder, or by updating the KeePassPasskey app.

## I tried creating a passkey but it failed saying one already exists

- When you register, the website can ask the authenticator not to create a second passkey for an account that already has one in the same place. It sends the list of credential IDs it already knows for you, and if KeePass holds a matching one, KeePassPasskey declines to create a duplicate and the operation fails. This is expected behaviour: it stops you from accumulating multiple passkeys for the same account in the same authenticator.
- To register again, open the **Passkeys** group, delete the existing entry for that site, and retry. The website will then no longer recognise an existing passkey and will let you create a new one.
- Alternatively, if you deliberately keep more than one passkey for the same account (for example the same account in separate databases), relax the **Allow duplicate passkeys** setting in the KeePassPasskey app so the registration is not blocked. See [Settings](user-guide.md#settings).

## Passkey prompts never show the Windows provider selection or KeePassPasskey

- A browser extension from another password manager (such as KeePassXC-Browser or any extension with passkey support) may be intercepting passkey requests before they reach Windows. When such an extension is active, the browser hands the passkey operation directly to that extension and Windows never gets involved, so KeePassPasskey is never called.
- Disable or remove any passkey-capable browser extensions and try again. If the Windows provider selection appears afterwards, the extension was the cause.

## The notification appears but clicking Create passkey does nothing

- Make sure a KeePass database is open. KeePassPasskey cannot save a passkey if no database is unlocked. KeePass only needs to be open during the passkey operation itself.
- If a database is open and the problem persists, check the log files for error messages.
