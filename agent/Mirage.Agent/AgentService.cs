using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Mirage.Agent;

/// <summary>Runs the file pipeline for as long as the host runs.</summary>
public sealed class AgentService(AgentConfig config, ILogger<AgentService> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var folders = Folders.ToWatch(config);
        var spool = new Spool(Path.Combine(config.ResolvedDataDir, "spool.jsonl"), config.MaxSpoolRecords, config.MaxKnownIds);
        using var http = CoreHttp.Create(new Uri(config.CoreUrl), TimeSpan.FromSeconds(90));
        var core = new CoreClient(http, () => Environment.GetEnvironmentVariable("MIRAGE_API_TOKEN"));
        using var pipeline = new FilePipeline(config, folders, spool, core, log);
        log.LogInformation("watching {Count} folder(s)", folders.Count);
        await pipeline.RunAsync(stoppingToken).ConfigureAwait(false);
    }
}
