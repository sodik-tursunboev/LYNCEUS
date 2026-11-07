using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Lynceus.Ipc;

namespace Lynceus.Agent;

/// <summary>Runs the core supervisor, the file pipeline and the pipe server for as long as the host runs.</summary>
public sealed class AgentService(AgentConfig config, ILogger<AgentService> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var dataDir = config.ResolvedDataDir;
        var token = TokenStore.Resolve(dataDir);
        var folders = Folders.ToWatch(config);
        var spool = new Spool(Path.Combine(dataDir, "spool.jsonl"), config.MaxSpoolRecords, config.MaxKnownIds);
        using var http = CoreHttp.Create(new Uri(config.CoreUrl), TimeSpan.FromSeconds(90));
        var core = new CoreClient(http, () => token);
        using var pipeline = new FilePipeline(config, folders, spool, core, log);
        var toasts = TryToasts(log);
        var flagged = new FlaggedStore(Path.Combine(dataDir, "flagged.json"));
        pipeline.Judged += outcome =>
        {
            if (outcome.Verdict.ActionId is { } actionId)
            {
                flagged.Add(actionId, outcome.Event.Path, outcome.Sha256, outcome.Event.Size, outcome.Event.ModifiedTicks);
            }

            Notify(toasts, ToastText.ForFile(outcome));
        };
        var quarantine = new QuarantineStore(Path.Combine(dataDir, "quarantine"));
        var responses = new ActionRunner(
            core, flagged, quarantine, config.ResponseMode, text => Notify(toasts, text),
            pipeline.Suppress, log);
        var secret = Endpoints.LoadOrCreateSecret(dataDir);
        var handler = new RequestHandler(core, () => pipeline.Stats, (host, state) => Notify(toasts, ToastText.ForBlock(host, state)));
        var server = new PipeServer(Endpoints.PipeName(), secret, handler, log);
        var supervisor = new CoreSupervisor(config, token, log, new RollingLog(Path.Combine(dataDir, "core.log")));
        var mail = new MailboxWatcher(core, text => Notify(toasts, text), log);
        log.LogInformation("watching {Count} folder(s)", folders.Count);
        await Task.WhenAll(
            pipeline.RunAsync(stoppingToken),
            server.RunAsync(stoppingToken),
            supervisor.RunAsync(stoppingToken),
            mail.RunAsync(TimeSpan.FromSeconds(30), stoppingToken),
            responses.RunAsync(TimeSpan.FromSeconds(3), stoppingToken)).ConfigureAwait(false);
    }

    private static WindowsToasts? TryToasts(ILogger log)
    {
        try
        {
            return new WindowsToasts();
        }
        catch (Exception e)
        {
            log.LogWarning("notifications are unavailable ({Type}); events are still logged and recorded", e.GetType().Name);
            return null;
        }
    }

    private void Notify(IToastSink? sink, (string Title, string Body)? text)
    {
        if (sink is null || text is not { } t)
        {
            return;
        }

        try
        {
            sink.Show(t.Title, t.Body);
            log.LogInformation("a notification was shown");
        }
        catch (Exception e)
        {
            log.LogWarning("a notification could not be shown ({Type})", e.GetType().Name);
        }
    }
}
