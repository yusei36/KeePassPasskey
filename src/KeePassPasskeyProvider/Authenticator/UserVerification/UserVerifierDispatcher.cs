// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassPasskeyProvider.Authenticator.Native;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyShared.Settings;
using Microsoft.Toolkit.Uwp.Notifications;
using Windows.UI.Notifications;

namespace KeePassPasskeyProvider.Authenticator.UserVerification;

internal static class UserVerifierDispatcher
{
    private static readonly IUserVerifier[] _verifiers =
    [
        new NotificationUserVerifier(),
        new WindowsHelloUserVerifier(),
    ];

    public static (int hr, string? selectedDatabaseId) VerifyForRegistration(
        nint pRequest, Guid transactionId,
        string rpId, string rpName, string uvUsername, string uvDisplayHint,
        IReadOnlyList<DatabaseInfo> databases)
        => DispatchRegistration(KeePassPasskeySettings.Current.RegistrationVerification,
            (IUserVerifier v, out string? sel) => v.VerifyForRegistration(pRequest, rpId, rpName, uvUsername, uvDisplayHint, transactionId, databases, out sel));

    public static int VerifyForSignIn(
        nint pRequest, Guid transactionId,
        string rpId, string uvUsername, string uvDisplayHint)
        => DispatchSignIn(KeePassPasskeySettings.Current.SignInVerification,
            v => v.VerifyForSignIn(pRequest, rpId, uvUsername, uvDisplayHint, transactionId));

    private delegate int VerifyRegistrationFunc(IUserVerifier v, out string? selectedDatabaseId);

    private static UserVerificationMode AdjustModeIfNotificationsDisabled(UserVerificationMode mode)
    {
        if (mode.HasFlag(UserVerificationMode.Notification))
        {
            var setting = ToastNotificationManagerCompat.CreateToastNotifier().Setting;
            if (setting != NotificationSetting.Enabled)
            {
                Log.Warn($"Notifications disabled ({setting}), falling back to Windows Hello", nameof(UserVerifierDispatcher));
                mode &= ~UserVerificationMode.Notification;
                mode |= UserVerificationMode.WindowsHello;
            }
        }
        return mode;
    }

    private static (int hr, string? selectedDatabaseId) DispatchRegistration(
        UserVerificationMode mode, VerifyRegistrationFunc call)
    {
        mode = AdjustModeIfNotificationsDisabled(mode);

        string? selected = null;
        foreach (var verifier in _verifiers)
        {
            if (!mode.HasFlag(verifier.Mode)) continue;
            int hr = call(verifier, out string? sel);
            Log.Info($"verifier={verifier.Mode} hr=0x{hr:X8}");
            if (sel != null) selected = sel;
            if (hr < HResults.S_OK) return (hr, null);
        }
        return (HResults.S_OK, selected);
    }

    private static int DispatchSignIn(UserVerificationMode mode, Func<IUserVerifier, int> call)
    {
        mode = AdjustModeIfNotificationsDisabled(mode);

        foreach (var verifier in _verifiers)
        {
            if (!mode.HasFlag(verifier.Mode)) continue;
            int hr = call(verifier);
            Log.Info($"verifier={verifier.Mode} hr=0x{hr:X8}");
            if (hr < HResults.S_OK) return hr;
        }
        return HResults.S_OK;
    }
}
