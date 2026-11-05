using Microsoft.Extensions.Logging;

namespace Mirage.Agent;

/// <summary>
/// Turns the core's live-mailbox status into notifications: one for each newly flagged email, and one when
/// a mailbox (Gmail or Outlook) has to be connected again. It never claims the mailbox is clean: if the core cannot be asked,
/// it says nothing and tries again. The first look only sets the baseline, so a restart does not replay
/// old alerts.
/// </summary>
public sealed class MailboxWatcher(CoreClient core, Action<(string Title, string Body)> show, ILogger log)
{
    private double? seenUpTo;
    private bool announcedReconnect;

    public async Task PollOnceAsync(CancellationToken ct)
    {
        var (status, value) = await core.MailboxStatusAsync(ct).ConfigureAwait(false);
        if (status != CoreStatus.Ok || value is null)
        {
            return;
        }

        if (value.State == "reauth_needed")
        {
            if (!announcedReconnect)
            {
                announcedReconnect = true;
                Show(ToastText.ForReconnect());
            }
        }
        else
        {
            announcedReconnect = false;
        }

        var newest = value.Flagged.Count == 0 ? 0 : value.Flagged.Max(f => f.At);
        if (seenUpTo is null)
        {
            seenUpTo = newest;
            return;
        }

        foreach (var mail in value.Flagged.Where(f => f.At > seenUpTo).OrderBy(f => f.At))
        {
            if (ToastText.ForMail(mail) is { } text)
            {
                Show(text);
            }
        }

        seenUpTo = Math.Max(seenUpTo.Value, newest);
    }

    public async Task RunAsync(TimeSpan every, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await PollOnceAsync(ct).ConfigureAwait(false);
                await Task.Delay(every, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception e)
            {
                log.LogWarning("the mailbox watcher step failed ({Type})", e.GetType().Name);
                await Task.Delay(every, CancellationToken.None).ConfigureAwait(false);
            }
        }
    }

    private void Show((string Title, string Body) text)
    {
        try
        {
            show(text);
        }
        catch (Exception e)
        {
            log.LogWarning("a mail notification could not be shown ({Type})", e.GetType().Name);
        }
    }
}
