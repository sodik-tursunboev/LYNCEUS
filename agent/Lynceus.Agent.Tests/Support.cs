using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Lynceus.Agent.Tests;

public sealed class TestDir : IDisposable
{
    public TestDir() => Path = Directory.CreateTempSubdirectory("lynceus-agent-").FullName;

    public string Path { get; }

    public string Sub(string name)
    {
        var path = System.IO.Path.Combine(Path, name);
        Directory.CreateDirectory(path);
        return path;
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
            // best effort
        }
        catch (UnauthorizedAccessException)
        {
            // best effort
        }
    }
}

public sealed record Seen(string Path, string? Name, string? Sha, string? Host, string? Auth, string? ContentType, byte[] Body, string Query = "", string? Method = null, string? Actor = null, string? FileId = null);

/// <summary>Stands in for the core: records every request and answers as scripted.</summary>
public sealed class FakeCore : HttpMessageHandler
{
    public const string Suspicious =
        """{"verdict":{"state":"SUSPICIOUS","risk_score":60,"signals":[{"rule_id":"email.pdf_javascript"}],"recommended_response":"WARN"},"reason":null,"inspected":true,"persisted":false}""";

    public ConcurrentQueue<Seen> Requests { get; } = new();

    public Func<Seen, HttpResponseMessage> Respond { get; set; } = _ => Json(Suspicious);

    public static HttpResponseMessage Json(string body, HttpStatusCode code = HttpStatusCode.OK) =>
        new(code) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    public static string Verdict(string state) =>
        $$"""{"verdict":{"state":"{{state}}","risk_score":null,"signals":[],"recommended_response":"NONE"},"reason":null,"inspected":true,"persisted":false}""";

    public IReadOnlyList<Seen> To(string path) => [.. Requests.Where(r => r.Path == path)];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(cancellationToken);
        string? Header(string name) => request.Headers.TryGetValues(name, out var v) ? v.FirstOrDefault() : null;
        var name = Header("X-Lynceus-Name");
        var seen = new Seen(
            request.RequestUri!.AbsolutePath,
            name is null ? null : Uri.UnescapeDataString(name),
            Header("X-Lynceus-Sha256"),
            Header("X-Lynceus-Origin-Host"),
            request.Headers.Authorization?.ToString(),
            request.Content?.Headers.ContentType?.MediaType,
            body,
            request.RequestUri.Query,
            request.Method.Method,
            Header("X-Lynceus-Actor"),
            Header("X-Lynceus-File-Id"));
        Requests.Enqueue(seen);
        return Respond(seen);
    }
}

public sealed class ListLogger : ILogger
{
    private readonly ConcurrentQueue<string> messages = new();

    public IReadOnlyList<string> Messages => [.. messages];

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
        messages.Enqueue(formatter(state, exception));
}

public static class Wait
{
    public static async Task Until(Func<bool> condition, string what, int milliseconds = 15_000)
    {
        var clock = Stopwatch.StartNew();
        while (!condition())
        {
            if (clock.ElapsedMilliseconds > milliseconds)
            {
                throw new Xunit.Sdk.XunitException("timed out waiting for: " + what);
            }

            await Task.Delay(20);
        }
    }
}

/// <summary>A watched folder, a data folder and a running pipeline with fast timings.</summary>
public sealed class Rig : IDisposable
{
    private readonly CancellationTokenSource stop = new();
    private Task? run;

    public Rig(string root, FakeCore? fake = null, Func<AgentConfig, AgentConfig>? tweak = null)
    {
        Watched = System.IO.Path.Combine(root, "watched");
        Directory.CreateDirectory(Watched);
        var data = System.IO.Path.Combine(root, "data");
        Config = new AgentConfig
        {
            DataDir = data,
            WatchFolders = [Watched],
            StableMillis = 60,
            TickMillis = 15,
            RetryBaseMillis = 30,
            RetryMaxMillis = 120,
            MaxAttempts = 3,
        };
        Config = tweak?.Invoke(Config) ?? Config;
        Fake = fake ?? new FakeCore();
        Spool = new Spool(System.IO.Path.Combine(data, "spool.jsonl"), Config.MaxSpoolRecords, Config.MaxKnownIds);
        var http = new HttpClient(Fake) { BaseAddress = new Uri("http://127.0.0.1:8765") };
        Pipeline = new FilePipeline(Config, Config.WatchFolders, Spool, new CoreClient(http, () => "test-token", verifyCore: false), Log);
        Pipeline.Judged += o =>
        {
            lock (Outcomes)
            {
                Outcomes.Add(o);
            }
        };
    }

    public string Watched { get; }

    public AgentConfig Config { get; }

    public FakeCore Fake { get; }

    public Spool Spool { get; }

    public FilePipeline Pipeline { get; }

    public ListLogger Log { get; } = new();

    public List<FileOutcome> Outcomes { get; } = [];

    public int Judged
    {
        get
        {
            lock (Outcomes)
            {
                return Outcomes.Count;
            }
        }
    }

    public string Write(string name, byte[] content)
    {
        var path = System.IO.Path.Combine(Watched, name);
        File.WriteAllBytes(path, content);
        return path;
    }

    public void Start()
    {
        Pipeline.Start(); // watching has begun before the caller writes anything
        run = Task.Run(() => Pipeline.RunAsync(stop.Token));
    }

    public async Task StopAsync()
    {
        await stop.CancelAsync();
        if (run is not null)
        {
            await run;
        }
    }

    public void Dispose()
    {
        stop.Cancel();
        try
        {
            run?.Wait(5000);
        }
        catch (AggregateException)
        {
            // stopping
        }

        Pipeline.Dispose();
    }
}
