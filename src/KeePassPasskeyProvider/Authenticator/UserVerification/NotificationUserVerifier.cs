// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Microsoft.Toolkit.Uwp.Notifications;
using Windows.UI.Notifications;
using KeePassPasskeyProvider.Authenticator.Native;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyShared.Settings;

namespace KeePassPasskeyProvider.Authenticator.UserVerification;

internal sealed class NotificationUserVerifier : IUserVerifier
{
    public UserVerificationMode Mode => UserVerificationMode.Notification;

    public int VerifyForRegistration(nint pRequest, string rpId, string rpName, string username, string displayHint,
        Guid transactionId, IReadOnlyList<DatabaseInfo> databases, out DatabaseInfo? selectedDatabase)
    {
        selectedDatabase = null;
        string site = rpName.Length > 0 ? rpName : rpId;
        string user = username.Length > 0 ? $" for {username}" : "";

        var (approved, sel) = ShowRegistrationToast(
            title: "Passkey creation requested",
            body: $"Create a passkey{user} on {site}.",
            confirmText: "Create passkey",
            tag: transactionId.ToString("N"),
            databases: databases);

        if (!approved) return HResults.NTE_USER_CANCELLED;
        selectedDatabase = sel;
        return HResults.S_OK;
    }

    public int VerifyForSignIn(nint pRequest, string rpId, string username, string displayHint, Guid transactionId)
    {
        string user = username.Length > 0 ? $" as {username}" : "";
        string hint = displayHint.Length > 0 && displayHint != rpId ? $"KeePass entry: {displayHint}" : "";
        return ShowToast(
            title: "Authentication requested",
            body:  $"Sign in{user} on {rpId}.",
            hint:  hint,
            confirmText: "Approve",
            tag: transactionId.ToString("N")) ? HResults.S_OK : HResults.NTE_USER_CANCELLED;
    }

    private static bool ShowToast(string title, string body, string confirmText, string tag, string hint = "")
    {
        int timeoutMilliseconds = KeePassPasskeySettings.Current.NotificationVerificationTimeoutMilliseconds;
        int timeoutSeconds      = timeoutMilliseconds / 1000;
        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var cts = new CancellationTokenSource();

        var initialData = new NotificationData();
        initialData.Values["progress"]   = "0";
        initialData.Values["statusText"] = $"Cancelling in {timeoutSeconds}s";

        var builder = new ToastContentBuilder()
            .SetToastScenario(ToastScenario.Alarm)
            .AddAudio(new ToastAudio { Silent = true })
            .AddText(title)
            .AddText(body);

        if (hint.Length > 0)
            builder.AddText(hint);

        builder.AddVisualChild(new AdaptiveProgressBar
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
            ExpirationTime = DateTimeOffset.Now.AddMilliseconds(timeoutMilliseconds)
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

    private static (bool Approved, DatabaseInfo? Selected) ShowRegistrationToast(
        string title, string body, string confirmText, string tag,
        IReadOnlyList<DatabaseInfo> databases)
    {
        int timeoutMilliseconds = KeePassPasskeySettings.Current.NotificationVerificationTimeoutMilliseconds;
        int timeoutSeconds = timeoutMilliseconds / 1000;
        var tcs = new TaskCompletionSource<(bool, DatabaseInfo?)>(TaskCreationOptions.RunContinuationsAsynchronously);
        var cts = new CancellationTokenSource();

        var initialData = new NotificationData();
        initialData.Values["progress"] = "0";
        initialData.Values["statusText"] = $"Cancelling in {timeoutSeconds}s";

        const string selectionBoxId = "dbPicker";

        var builder = new ToastContentBuilder()
            .SetToastScenario(ToastScenario.Alarm)
            .AddAudio(new ToastAudio { Silent = true })
            .AddText(title)
            .AddText(body);

        var selectionBox = new ToastSelectionBox(selectionBoxId)
        {
            DefaultSelectionBoxItemId = "0",
            Title = "Save to database"
        };
        for (int i = 0; i < databases.Count; i++)
            selectionBox.Items.Add(new ToastSelectionBoxItem(i.ToString(), databases[i].Name));
        builder.AddToastInput(selectionBox);

        builder.AddVisualChild(new AdaptiveProgressBar
            {
                Value = new BindableProgressBarValue("progress"),
                ValueStringOverride = char.ConvertFromUtf32(0x2003),  // U+2003 EM SPACE (hides % value)
                Status = new BindableString("statusText"),
            })
            .AddButton(new ToastButton()
                .SetContent(confirmText)
                .AddArgument("action", "allow"))
            .AddButton(new ToastButton()
                .SetContent("Cancel")
                .AddArgument("action", "deny"));

        var toast = new ToastNotification(builder.GetXml())
        {
            Tag = tag,
            Data = initialData,
            ExpirationTime = DateTimeOffset.Now.AddMilliseconds(timeoutMilliseconds)
        };

        toast.Activated += (s, a) =>
        {
            cts.Cancel();
            var args = ((ToastActivatedEventArgs)a).Arguments;
            var inputs = ((ToastActivatedEventArgs)a).UserInput;
            string? indexStr = inputs.ContainsKey(selectionBoxId) ? inputs[selectionBoxId]?.ToString() : "0";
            int idx = int.TryParse(indexStr, out int idxParsed) && idxParsed >= 0 && idxParsed < databases.Count ? idxParsed : 0;
            DatabaseInfo selectedDb = databases[idx];
            var selected = new DatabaseInfo { Id = selectedDb.Id, Name = selectedDb.Name };
            if (string.IsNullOrEmpty(args)) { tcs.TrySetResult((true, selected)); return; }
            var parsed = ToastArguments.Parse(args);
            bool allowed = parsed.TryGetValue("action", out var action) && action == "allow";
            tcs.TrySetResult((allowed, selected));
        };
        toast.Dismissed += (s, a) => { cts.Cancel(); tcs.TrySetResult((false, null)); };
        toast.Failed    += (s, a) => { cts.Cancel(); tcs.TrySetResult((false, null)); };

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
                update.Values["progress"] = FormattableString.Invariant($"{(double)elapsed / timeoutSeconds}");
                update.Values["statusText"] = $"Cancelling in {remaining}s";
                notifier.Update(update, tag);
            }
            notifier.Hide(toast);
            tcs.TrySetResult((false, null));
        });

        return tcs.Task.GetAwaiter().GetResult();
    }
}
