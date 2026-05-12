// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassPasskeyProvider.Authenticator.Native;
using KeePassPasskeyShared;
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

    public static int VerifyForRegistration(
        nint pRequest, Guid transactionId,
        string rpId, string rpName, string uvUsername, string uvDisplayHint)
        => Dispatch(KeePassPasskeySettings.Current.RegistrationVerification,
            v => v.VerifyForRegistration(pRequest, rpId, rpName, uvUsername, uvDisplayHint, transactionId));

    public static int VerifyForSignIn(
        nint pRequest, Guid transactionId,
        string rpId, string uvUsername, string uvDisplayHint)
        => Dispatch(KeePassPasskeySettings.Current.SignInVerification,
            v => v.VerifyForSignIn(pRequest, rpId, uvUsername, uvDisplayHint, transactionId));

    private static int Dispatch(UserVerificationMode mode, Func<IUserVerifier, int> call)
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

        foreach (var verifier in _verifiers)
        {
            if (!mode.HasFlag(verifier.Mode)) continue;
            int hr = call(verifier);
            if (hr < HResults.S_OK) return hr;
        }
        return HResults.S_OK;
    }
}
