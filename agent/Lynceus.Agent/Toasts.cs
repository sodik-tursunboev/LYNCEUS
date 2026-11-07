using System.Globalization;
using System.Security;
using Microsoft.Win32;
using Windows.Data.Xml.Dom;
using Windows.UI.Notifications;

namespace Lynceus.Agent;

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
        if (state is not ("MALICIOUS" or "SUSPICIOUS") || o.Verdict.AllowListed)
        {
            return null; // and a file you told Lynceus to stop flagging stays quiet
        }

        var title = state == "MALICIOUS" ? "Lynceus: dangerous file" : "Lynceus: suspicious file";
        var reason = o.Verdict.Reasons is { Count: > 0 } reasons ? reasons[0] : "Several signs of a malicious file.";
        var tail = o.Verdict.ActionId is not null ? "\nWaiting for your decision in the Lynceus console." : "\nNothing was moved or deleted.";
        return (title, Cut(Clean(o.Event.Name), 80) + "\n" + Cut(reason, 160) + tail);
    }

    /// <summary>A flagged email: when, how bad, and the names of the signs. No sender, subject or address is ever known here.</summary>
    public static (string Title, string Body)? ForMail(FlaggedMail mail)
    {
        if (mail.State is not ("MALICIOUS" or "SUSPICIOUS"))
        {
            return null;
        }

        var signs = mail.Rules.Count == 0 ? "several signs of phishing" : string.Join(", ", mail.Rules.Take(3).Select(Friendly));
        var score = mail.Score is { } s ? $" (score {s})" : string.Empty;
        return (
            mail.State == "MALICIOUS" ? "Lynceus: dangerous email" : "Lynceus: suspicious email",
            $"A new email in your inbox{score}: {signs}. Open it with care. Nothing was moved or deleted.");
    }

    public static (string Title, string Body) ForReconnect() =>
        ("Lynceus: your mailbox needs to be connected again", "Access expired or was revoked, so new mail is not being checked. Run: python -m core.mailbox connect (add --provider outlook for Outlook)");

    internal static string Friendly(string rule) => Cut(Clean(rule[(rule.LastIndexOf('.') + 1)..].Replace('_', ' ')), 60);

    public static (string Title, string Body)? ForBlock(string host, string state) =>
        state is "MALICIOUS" or "SUSPICIOUS"
            ? (state == "MALICIOUS" ? "Lynceus stopped a phishing page" : "Lynceus warned about a suspicious page", Cut(Clean(host), 120))
            : null;

    /// <summary>Control and format characters (every bidi override and mark, zero-width and joiner) become "?": a name cannot reorder or hide what the toast says.</summary>
    internal static string Clean(string text) =>
        new(text.Select(c => char.IsControl(c) || CharUnicodeInfo.GetUnicodeCategory(c) == UnicodeCategory.Format ? '?' : c).ToArray());

    internal static string Cut(string text, int max) => text.Length <= max ? text : text[..(max - 1)] + "…";
}

/// <summary>
/// Windows toast notifications from an ordinary desktop program: a name registered under the
/// current user so Windows shows "Lynceus" as the sender, then the notifier for that name. If it
/// fails (focus assist, policy, an elevated process) the event is still logged and recorded.
/// </summary>
public sealed class WindowsToasts : IToastSink
{
    public const string AppId = "Lynceus.Agent";
    private readonly string registryBase;

    public WindowsToasts(string registryBase = @"Software\Classes\AppUserModelId")
    {
        this.registryBase = registryBase;
        using var key = Registry.CurrentUser.CreateSubKey(registryBase + "\\" + AppId);
        key.SetValue("DisplayName", "Lynceus");
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
