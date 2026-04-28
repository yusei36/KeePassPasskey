using Windows.Data.Xml.Dom;
using Windows.UI.Notifications;
using KeePassPasskey.Shared;
using KeePassPasskey.Shared.Ipc;

namespace KeePassPasskeyProvider.Util;

internal static class Notifier
{
    private static readonly bool _enabled = AppSettings.Current.ShowErrorNotifications;

    public static void ShowMakeCredentialError(string rpId, PipeErrorCode? code, string? errorMessage = null) =>
        ShowError("Passkey creation failed", ErrorBody(code, rpId, errorMessage));

    public static void ShowGetAssertionError(string rpId, PipeErrorCode? code, string? errorMessage = null) =>
        ShowError("Sign-in failed", ErrorBody(code, rpId, errorMessage));

    public static void ShowPipeError(string operation) =>
        ShowError($"{operation} failed", "KeePass is not running or the database is locked.");

    private static string ErrorBody(PipeErrorCode? code, string rpId, string? errorMessage)
    {
        var detail = string.IsNullOrWhiteSpace(errorMessage) ? "" : $"\n{errorMessage}";
        return code switch
        {
            PipeErrorCode.DbLocked      => "The KeePass database is locked. Please unlock KeePass and try again.",
            PipeErrorCode.Duplicate     => $"A passkey for {rpId} already exists.",
            PipeErrorCode.NotFound      => $"No passkey found for {rpId}.",
            PipeErrorCode.InternalError => "An internal error occurred in KeePass:" + detail,
            _                           => "An unexpected error occurred:" + detail,
        };
    }

    private static void ShowError(string title, string body)
    {
        if (!_enabled) return;
        try
        {
            var xml = $"""
                <toast>
                  <visual>
                    <binding template="ToastGeneric">
                      <text>{Escape(title)}</text>
                      <text>{Escape(body)}</text>
                    </binding>
                  </visual>
                </toast>
                """;

            var doc = new XmlDocument();
            doc.LoadXml(xml);
            var notification = new ToastNotification(doc)
            {
                ExpirationTime = DateTimeOffset.Now.AddSeconds(30)
            };
            ToastNotificationManager.CreateToastNotifier().Show(notification);
        }
        catch (Exception ex)
        {
            Log.Warn($"toast failed: {ex.Message}");
        }
    }

    private static string Escape(string s) =>
        s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");
}
