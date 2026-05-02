using Microsoft.Toolkit.Uwp.Notifications;
using Windows.UI.Notifications;
using KeePassPasskeyProvider.Authenticator.Native;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider.Authenticator.UserVerification;

internal sealed class NotificationUserVerifier : IUserVerifier
{
    public UserVerificationMode Mode => UserVerificationMode.Notification;

    public int VerifyForRegistration(nint pRequest, string rpId, string rpName, string username, string displayHint, Guid transactionId)
    {
        string site = rpName.Length > 0 ? rpName : rpId;
        string user = username.Length > 0 ? $" for {username}" : "";
        return ShowToast(
            title: "Passkey creation requested",
            body:  $"Create a passkey{user} on {site}.",
            confirmText: "Create passkey",
            tag: transactionId.ToString("N")) ? HResults.S_OK : HResults.NTE_USER_CANCELLED;
    }

    public int VerifyForSignIn(nint pRequest, string rpId, string username, string displayHint, Guid transactionId)
    {
        string user = username.Length > 0 ? $" as {username}" : "";
        return ShowToast(
            title: "Authentication requested",
            body:  $"Sign in{user} on {rpId}.",
            confirmText: "Approve",
            tag: transactionId.ToString("N")) ? HResults.S_OK : HResults.NTE_USER_CANCELLED;
    }

    private static bool ShowToast(string title, string body, string confirmText, string tag)
    {
        int timeoutSeconds = AppSettings.Current.NotificationVerificationTimeoutSeconds;
        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var cts = new CancellationTokenSource();

        var initialData = new NotificationData();
        initialData.Values["progress"]   = "0";
        initialData.Values["statusText"] = $"Cancelling in {timeoutSeconds}s";

        var builder = new ToastContentBuilder()
            .SetToastScenario(ToastScenario.Alarm)
            .AddAudio(new ToastAudio { Silent = true })
            .AddText(title)
            .AddText(body)
            .AddVisualChild(new AdaptiveProgressBar
            {
                Value               = new BindableProgressBarValue("progress"),
                ValueStringOverride = char.ConvertFromUtf32(0x2003), // U+2003 EM SPACE (hides % value)
                Status              = new BindableString("statusText"),
            })
            .AddButton(new ToastButton()
                .SetContent(confirmText)
                .AddArgument("action", "allow"))
            .AddButton(new ToastButton()
                .SetContent("Cancel")
                .AddArgument("action", "deny"));

        var toast = new ToastNotification(builder.GetXml())
        {
            Tag            = tag,
            Data           = initialData,
            ExpirationTime = DateTimeOffset.Now.AddSeconds(timeoutSeconds)
        };

        toast.Activated += (s, a) =>
        {
            cts.Cancel();
            var args = ((ToastActivatedEventArgs)a).Arguments;
            if (string.IsNullOrEmpty(args)) { tcs.TrySetResult(true); return; }
            var parsed = ToastArguments.Parse(args);
            tcs.TrySetResult(parsed.TryGetValue("action", out var action) && action == "allow");
        };
        toast.Dismissed += (s, a) => { cts.Cancel(); tcs.TrySetResult(false); };
        toast.Failed    += (s, a) => { cts.Cancel(); tcs.TrySetResult(false); };

        var notifier = ToastNotificationManagerCompat.CreateToastNotifier();
        notifier.Show(toast);

        _ = Task.Run(async () =>
        {
            for (int remaining = timeoutSeconds - 1; remaining >= 0; remaining--)
            {
                try { await Task.Delay(1000, cts.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }

                int elapsed = timeoutSeconds - remaining;
                var update = new NotificationData();
                update.Values["progress"]   = FormattableString.Invariant($"{(double)elapsed / timeoutSeconds}");
                update.Values["statusText"] = $"Cancelling in {remaining}s";
                notifier.Update(update, tag);
            }
            notifier.Hide(toast);
            tcs.TrySetResult(false);
        });

        return tcs.Task.GetAwaiter().GetResult();
    }
}
