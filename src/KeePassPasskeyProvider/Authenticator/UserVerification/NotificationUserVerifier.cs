// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Microsoft.Toolkit.Uwp.Notifications;
using Windows.UI.Notifications;
using KeePassPasskeyProvider.Authenticator.Native;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyShared.Settings;

namespace KeePassPasskeyProvider.Authenticator.UserVerification;

internal sealed class NotificationUserVerifier : IUserVerifier
{
    public UserVerificationMode Mode => UserVerificationMode.Notification;

    // Windows toast selection boxes (ToastSelectionBox) are hard-limited to 5 items; adding a 6th
    // throws. We cap what we add and log when there is more so a match-heavy site never fails.
    private const int MaxToastSelectionItems = 5;

    // What the user chose on the registration toast.
    private enum RegistrationAction { Deny, CreateNew, AddToExisting }

    public int VerifyForRegistration(nint pRequest, string rpId, string rpName, string username, string displayHint,
        Guid transactionId, IReadOnlyList<DatabaseInfo> databases, IReadOnlyList<EntryMatchInfo> candidateEntries,
        out DatabaseInfo? selectedDatabase, out EntryTargetInfo? selectedEntry)
    {
        selectedDatabase = null;
        selectedEntry = null;
        string site = rpName.Length > 0 ? rpName : rpId;
        string user = username.Length > 0 ? $" for {username}" : "";
        bool hasCandidates = candidateEntries != null && candidateEntries.Count > 0;
        string tag = transactionId.ToString("N");

        var (action, sel) = ShowRegistrationToast(
            title: "Passkey creation requested",
            body: $"Create a passkey{user} on {site}.",
            confirmText: "Create passkey",
            tag: tag,
            databases: databases,
            offerAddToExisting: hasCandidates);

        if (action == RegistrationAction.Deny) return HResults.NTE_USER_CANCELLED;

        if (action == RegistrationAction.AddToExisting)
        {
            var chosen = ShowEntryPickerToast(
                title: "Choose an entry",
                body: $"Save the passkey for {site} onto an existing entry.",
                tag: tag,
                candidates: candidateEntries!);
            if (chosen == null) return HResults.NTE_USER_CANCELLED;
            selectedEntry = new EntryTargetInfo { EntryUuid = chosen.EntryUuid, DatabaseId = chosen.DatabaseId };
            return HResults.S_OK;
        }

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
        int timeoutSeconds = TimeoutSeconds();
        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var cts = new CancellationTokenSource();

        var builder = new ToastContentBuilder()
            .SetToastScenario(ToastScenario.Alarm)
            .AddAudio(new ToastAudio { Silent = true })
            .AddText(title)
            .AddText(body);

        if (hint.Length > 0)
            builder.AddText(hint);

        AddProgressAndButtons(builder, confirmText);

        var toast = BuildToast(builder, tag, timeoutSeconds);

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
        RunCountdown(notifier, toast, tag, timeoutSeconds, cts.Token, () => tcs.TrySetResult(false));

        return tcs.Task.GetAwaiter().GetResult();
    }

    private static (RegistrationAction Action, DatabaseInfo? Selected) ShowRegistrationToast(
        string title, string body, string confirmText, string tag,
        IReadOnlyList<DatabaseInfo> databases, bool offerAddToExisting)
    {
        int timeoutSeconds = TimeoutSeconds();
        var tcs = new TaskCompletionSource<(RegistrationAction, DatabaseInfo?)>(TaskCreationOptions.RunContinuationsAsynchronously);
        var cts = new CancellationTokenSource();

        const string selectionBoxId = "dbPicker";

        var builder = new ToastContentBuilder()
            .SetToastScenario(ToastScenario.Alarm)
            .AddAudio(new ToastAudio { Silent = true })
            .AddText(title)
            .AddText(body);

        if (databases.Count > 1)
        {
            var selectionBox = new ToastSelectionBox(selectionBoxId)
            {
                DefaultSelectionBoxItemId = "0",
                Title = "Save to database"
            };
            int dbCount = Math.Min(databases.Count, MaxToastSelectionItems);
            for (int i = 0; i < dbCount; i++)
                selectionBox.Items.Add(new ToastSelectionBoxItem(i.ToString(), databases[i].Name));
            if (databases.Count > MaxToastSelectionItems)
                Log.Warn($"Database picker truncated to {MaxToastSelectionItems} of {databases.Count} open databases", nameof(NotificationUserVerifier));
            builder.AddToastInput(selectionBox);
        }

        builder.AddVisualChild(ProgressBar())
            .AddButton(new ToastButton()
                .SetContent(confirmText)
                .AddArgument("action", "allow"));

        if (offerAddToExisting)
            builder.AddButton(new ToastButton()
                .SetContent("Add to existing")
                .AddArgument("action", "existing"));

        builder.AddButton(new ToastButton()
            .SetContent("Cancel")
            .AddArgument("action", "deny"));

        var toast = BuildToast(builder, tag, timeoutSeconds);

        toast.Activated += (s, a) =>
        {
            cts.Cancel();
            var args = ((ToastActivatedEventArgs)a).Arguments;
            var inputs = ((ToastActivatedEventArgs)a).UserInput;
            string? indexStr = inputs.ContainsKey(selectionBoxId) ? inputs[selectionBoxId]?.ToString() : "0";
            int idx = int.TryParse(indexStr, out int idxParsed) && idxParsed >= 0 && idxParsed < databases.Count ? idxParsed : 0;
            DatabaseInfo selectedDb = databases[idx];
            var selected = new DatabaseInfo { Id = selectedDb.Id, Name = selectedDb.Name };

            var parsed = string.IsNullOrEmpty(args) ? null : ToastArguments.Parse(args);
            string action = parsed != null && parsed.TryGetValue("action", out var act) ? act : "allow";
            var result = action switch
            {
                "existing" => RegistrationAction.AddToExisting,
                "deny"     => RegistrationAction.Deny,
                _          => RegistrationAction.CreateNew,
            };
            tcs.TrySetResult((result, selected));
        };
        toast.Dismissed += (s, a) => { cts.Cancel(); tcs.TrySetResult((RegistrationAction.Deny, null)); };
        toast.Failed    += (s, a) => { cts.Cancel(); tcs.TrySetResult((RegistrationAction.Deny, null)); };

        var notifier = ToastNotificationManagerCompat.CreateToastNotifier();
        notifier.Show(toast);
        RunCountdown(notifier, toast, tag, timeoutSeconds, cts.Token, () => tcs.TrySetResult((RegistrationAction.Deny, null)));

        return tcs.Task.GetAwaiter().GetResult();
    }

    // Second toast: pick which existing entry to attach the passkey to. Modeled on the database
    // picker. Entries that already hold a passkey are labelled so overwriting is an informed choice.
    private static EntryMatchInfo? ShowEntryPickerToast(
        string title, string body, string tag, IReadOnlyList<EntryMatchInfo> candidates)
    {
        int timeoutSeconds = TimeoutSeconds();
        var tcs = new TaskCompletionSource<EntryMatchInfo?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var cts = new CancellationTokenSource();

        const string selectionBoxId = "entryPicker";
        bool showDbName = false;
        for (int i = 1; i < candidates.Count; i++)
            if (candidates[i].DatabaseId != candidates[0].DatabaseId) { showDbName = true; break; }

        var builder = new ToastContentBuilder()
            .SetToastScenario(ToastScenario.Alarm)
            .AddAudio(new ToastAudio { Silent = true })
            .AddText(title)
            .AddText(body);

        var selectionBox = new ToastSelectionBox(selectionBoxId)
        {
            DefaultSelectionBoxItemId = "0",
            Title = "Save to entry"
        };
        int shown = Math.Min(candidates.Count, MaxToastSelectionItems);
        for (int i = 0; i < shown; i++)
            selectionBox.Items.Add(new ToastSelectionBoxItem(i.ToString(), EntryLabel(candidates[i], showDbName)));
        if (candidates.Count > MaxToastSelectionItems)
            Log.Warn($"Entry picker truncated to {MaxToastSelectionItems} of {candidates.Count} matching entries", nameof(NotificationUserVerifier));
        builder.AddToastInput(selectionBox);

        builder.AddVisualChild(ProgressBar())
            .AddButton(new ToastButton()
                .SetContent("Save to entry")
                .AddArgument("action", "allow"))
            .AddButton(new ToastButton()
                .SetContent("Cancel")
                .AddArgument("action", "deny"));

        var toast = BuildToast(builder, tag, timeoutSeconds);

        toast.Activated += (s, a) =>
        {
            cts.Cancel();
            var args = ((ToastActivatedEventArgs)a).Arguments;
            var inputs = ((ToastActivatedEventArgs)a).UserInput;
            var parsed = string.IsNullOrEmpty(args) ? null : ToastArguments.Parse(args);
            bool allowed = parsed == null || (parsed.TryGetValue("action", out var action) && action == "allow");
            if (!allowed) { tcs.TrySetResult(null); return; }

            string? indexStr = inputs.ContainsKey(selectionBoxId) ? inputs[selectionBoxId]?.ToString() : "0";
            int idx = int.TryParse(indexStr, out int idxParsed) && idxParsed >= 0 && idxParsed < candidates.Count ? idxParsed : 0;
            tcs.TrySetResult(candidates[idx]);
        };
        toast.Dismissed += (s, a) => { cts.Cancel(); tcs.TrySetResult(null); };
        toast.Failed    += (s, a) => { cts.Cancel(); tcs.TrySetResult(null); };

        var notifier = ToastNotificationManagerCompat.CreateToastNotifier();
        notifier.Show(toast);
        RunCountdown(notifier, toast, tag, timeoutSeconds, cts.Token, () => tcs.TrySetResult(null));

        return tcs.Task.GetAwaiter().GetResult();
    }

    private static string EntryLabel(EntryMatchInfo entry, bool showDbName)
    {
        string title = string.IsNullOrEmpty(entry.Title) ? "(untitled)" : entry.Title;
        if (showDbName && !string.IsNullOrEmpty(entry.DatabaseName))
            title = $"{entry.DatabaseName}: {title}";
        return entry.HasPasskey ? $"{title} [overwrite passkey]" : title;
    }

    private static int TimeoutSeconds()
        => KeePassPasskeySettings.Current.NotificationVerificationTimeoutMilliseconds / 1000;

    private static AdaptiveProgressBar ProgressBar() => new AdaptiveProgressBar
    {
        Value               = new BindableProgressBarValue("progress"),
        ValueStringOverride = char.ConvertFromUtf32(0x2003), // U+2003 EM SPACE (hides % value)
        Status              = new BindableString("statusText"),
    };

    private static void AddProgressAndButtons(ToastContentBuilder builder, string confirmText)
        => builder.AddVisualChild(ProgressBar())
            .AddButton(new ToastButton().SetContent(confirmText).AddArgument("action", "allow"))
            .AddButton(new ToastButton().SetContent("Cancel").AddArgument("action", "deny"));

    private static ToastNotification BuildToast(ToastContentBuilder builder, string tag, int timeoutSeconds)
    {
        var initialData = new NotificationData();
        initialData.Values["progress"]   = "0";
        initialData.Values["statusText"] = $"Cancelling in {timeoutSeconds}s";

        return new ToastNotification(builder.GetXml())
        {
            Tag            = tag,
            Data           = initialData,
            ExpirationTime = DateTimeOffset.Now.AddSeconds(timeoutSeconds),
        };
    }

    // Drives the countdown progress bar and hides the toast + fires onTimeout when it elapses.
    // Cancelled (via the token) as soon as the user acts on the toast.
    private static void RunCountdown(ToastNotifierCompat notifier, ToastNotification toast, string tag,
        int timeoutSeconds, CancellationToken token, Action onTimeout)
    {
        _ = Task.Run(async () =>
        {
            for (int remaining = timeoutSeconds - 1; remaining >= 0; remaining--)
            {
                try { await Task.Delay(1000, token).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }

                int elapsed = timeoutSeconds - remaining;
                var update = new NotificationData();
                update.Values["progress"]   = FormattableString.Invariant($"{(double)elapsed / timeoutSeconds}");
                update.Values["statusText"] = $"Cancelling in {remaining}s";
                notifier.Update(update, tag);
            }
            notifier.Hide(toast);
            onTimeout();
        });
    }
}
