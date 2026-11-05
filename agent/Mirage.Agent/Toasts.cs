using System.Security;
using Microsoft.Win32;
using Windows.Data.Xml.Dom;
using Windows.UI.Notifications;

namespace Mirage.Agent;

public interface IToastSink
{
    void Show(string title, string body);
}

/// <summary>The words of a notification: short, and only facts the user can see on their own disk or screen.</summary>
public static class ToastText
{
    /// <summary>Null when the verdict needs no notification (only SUSPICIOUS and MALICIOUS do).</summary>
    public static (string Title, string Body)? ForFile(FileOutcome o)
    {
        var state = o.Verdict.State;
        if (state is not ("MALICIOUS" or "SUSPICIOUS"))
        {
            return null;
        }

        var title = state == "MALICIOUS" ? "MIRAGE: dangerous file" : "MIRAGE: suspicious file";
        var reason = o.Verdict.Reasons is { Count: > 0 } reasons ? reasons[0] : "Several signs of a malicious file.";
        return (title, Cut(Clean(o.Event.Name), 80) + "\n" + Cut(reason, 160) + "\nNothing was moved or deleted.");
    }

    public static (string Title, string Body)? ForBlock(string host, string state) =>
        state is "MALICIOUS" or "SUSPICIOUS"
            ? (state == "MALICIOUS" ? "MIRAGE stopped a phishing page" : "MIRAGE warned about a suspicious page", Cut(Clean(host), 120))
            : null;

    internal static string Clean(string text) => new(text.Select(c => char.IsControl(c) || c is '‮' or '‭' or '⁦' or '⁧' or '⁨' or '⁩' ? '?' : c).ToArray());

    internal static string Cut(string text, int max) => text.Length <= max ? text : text[..(max - 1)] + "…";
}

/// <summary>
/// Windows toast notifications from an ordinary desktop program: a name registered under the
/// current user so Windows shows "MIRAGE" as the sender, then the notifier for that name. If it
/// fails (focus assist, policy, an elevated process) the event is still logged and recorded.
/// </summary>
public sealed class WindowsToasts : IToastSink
{
    public const string AppId = "Mirage.Agent";
    private readonly string registryBase;

    public WindowsToasts(string registryBase = @"Software\Classes\AppUserModelId")
    {
        this.registryBase = registryBase;
        using var key = Registry.CurrentUser.CreateSubKey(registryBase + "\\" + AppId);
        key.SetValue("DisplayName", "MIRAGE");
    }

    public static string Xml(string title, string body) =>
        $"<toast><visual><binding template=\"ToastGeneric\"><text>{SecurityElement.Escape(title)}</text><text>{SecurityElement.Escape(body)}</text></binding></visual></toast>";

    public void Show(string title, string body)
    {
        var xml = new XmlDocument();
        xml.LoadXml(Xml(title, body));
        ToastNotificationManager.CreateToastNotifier(AppId).Show(new ToastNotification(xml));
    }
}
