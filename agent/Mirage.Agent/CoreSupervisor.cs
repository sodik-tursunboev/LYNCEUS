using System.Diagnostics;
using System.Globalization;
using Microsoft.Extensions.Logging;

namespace Mirage.Agent;

/// <summary>
/// Keeps the core running without a console: starts it if nothing answers on its port, starts it
/// again after it dies (pausing longer if it keeps dying at once), and stops what it started when
/// the agent stops. The token reaches the child by environment variable, never on a command line.
/// If something else already answers, it leaves that alone.
/// </summary>
public sealed class CoreSupervisor(AgentConfig config, string token, ILogger log, RollingLog? output = null)
{
    private Process? child;
    private TimeSpan pause = TimeSpan.FromSeconds(1);

    public int Starts { get; private set; }

    public async Task RunAsync(CancellationToken ct)
    {
        if (config.CoreCommand is null)
        {
            return;
        }

        using var http = CoreHttp.Create(new Uri(config.CoreUrl), TimeSpan.FromSeconds(1));
        try
        {
            while (!ct.IsCancellationRequested)
            {
                if (await IsUpAsync(http, ct).ConfigureAwait(false))
                {
                    pause = TimeSpan.FromSeconds(1);
                    await Task.Delay(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
                    continue;
                }

                if (child is null or { HasExited: true })
                {
                    var started = Stopwatch.GetTimestamp();
                    Start();
                    await WaitUntilUpAsync(http, TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
                    if (child is { HasExited: true } && Stopwatch.GetElapsedTime(started) < TimeSpan.FromSeconds(10))
                    {
                        log.LogWarning("the core stopped right after starting; waiting {Seconds}s before trying again", pause.TotalSeconds);
                        await Task.Delay(pause, ct).ConfigureAwait(false);
                        pause = TimeSpan.FromTicks(Math.Min(pause.Ticks * 2, TimeSpan.FromSeconds(60).Ticks));
                    }
                }
                else
                {
                    await Task.Delay(TimeSpan.FromSeconds(1), ct).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // stopping
        }
        finally
        {
            Stop();
        }
    }

    public void Stop()
    {
        if (child is { HasExited: false })
        {
            try
            {
                child.Kill(entireProcessTree: true);
                child.WaitForExit(5000);
            }
            catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                // already gone
            }
        }

        child?.Dispose();
        child = null;
    }

    internal ProcessStartInfo BuildStartInfo()
    {
        var start = new ProcessStartInfo(config.CoreCommand!)
        {
            WorkingDirectory = config.CoreWorkingDir!,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in config.CoreArgs)
        {
            start.ArgumentList.Add(argument);
        }

        // Nothing the agent inherited may change what the core imports or runs first (PYTHONPATH, PYTHONSTARTUP, ...),
        // and the core ignores per-user site-packages: it runs with the user's rights and the user's token.
        foreach (var name in start.Environment.Keys.Where(k => k.StartsWith("PYTHON", StringComparison.OrdinalIgnoreCase)).ToList())
        {
            start.Environment.Remove(name);
        }

        start.Environment["PYTHONNOUSERSITE"] = "1";
        start.Environment["MIRAGE_API_TOKEN"] = token;
        start.Environment["MIRAGE_INTEL_DEADLINE"] = config.CoreIntelDeadlineSeconds.ToString(CultureInfo.InvariantCulture);
        return start;
    }

    private void Start()
    {
        var start = BuildStartInfo();
        try
        {
            child?.Dispose();
            child = Process.Start(start);
            if (child is null)
            {
                return;
            }

            Starts++;
            child.OutputDataReceived += (_, e) => Relay(e.Data);
            child.ErrorDataReceived += (_, e) => Relay(e.Data);
            child.BeginOutputReadLine();
            child.BeginErrorReadLine();
            log.LogInformation("started the core (attempt {Count})", Starts);
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            log.LogError("could not start the core ({Type})", e.GetType().Name);
        }
    }

    private void Relay(string? line)
    {
        if (line is not null)
        {
            output?.WriteLine(line); // the core redacts its own log lines
        }
    }

    private static async Task<bool> IsUpAsync(HttpClient http, CancellationToken ct)
    {
        try
        {
            using var response = await http.GetAsync("/health", ct).ConfigureAwait(false);
            return response.IsSuccessStatusCode;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            return false;
        }
    }

    private async Task WaitUntilUpAsync(HttpClient http, TimeSpan limit, CancellationToken ct)
    {
        var clock = Stopwatch.StartNew();
        while (clock.Elapsed < limit && child is { HasExited: false })
        {
            if (await IsUpAsync(http, ct).ConfigureAwait(false))
            {
                return;
            }

            await Task.Delay(250, ct).ConfigureAwait(false);
        }
    }
}
