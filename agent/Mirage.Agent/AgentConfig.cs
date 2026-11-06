using System.Text.Json;

namespace Mirage.Agent;

public sealed class ConfigException(string message) : Exception(message);

/// <summary>
/// Settings from %LOCALAPPDATA%\Mirage\agent.json. Unknown keys and out-of-range values are
/// refused (the agent does not start on a config it cannot trust); a missing file means defaults.
/// </summary>
public sealed record AgentConfig
{
    /// <summary>Where the core listens. Loopback only, checked here and again on every connection.</summary>
    public string CoreUrl { get; init; } = "http://127.0.0.1:8765";

    /// <summary>Folders to watch. Empty means the Downloads known folder.</summary>
    public string[] WatchFolders { get; init; } = [];

    public bool IncludeSubfolders { get; init; }

    /// <summary>A file counts as finished when nothing has touched it for this long.</summary>
    public int StableMillis { get; init; } = 1000;

    /// <summary>Stop trying to open a file that stays locked for this long.</summary>
    public int GiveUpSeconds { get; init; } = 600;

    public int TickMillis { get; init; } = 250;

    /// <summary>Files up to this size are sent to the core for inspection; larger ones are described only.</summary>
    public long MaxInspectBytes { get; init; } = (16 * 1024 * 1024) - 4096;

    public int WatcherBufferBytes { get; init; } = 64 * 1024;

    public int MaxPendingPaths { get; init; } = 10_000;

    public int MaxSpoolRecords { get; init; } = 10_000;

    public int MaxKnownIds { get; init; } = 20_000;

    public int MaxRescanFiles { get; init; } = 5_000;

    /// <summary>First wait after the core fails to answer; it doubles up to RetryMaxMillis.</summary>
    public int RetryBaseMillis { get; init; } = 1000;

    public int RetryMaxMillis { get; init; } = 60_000;

    /// <summary>How often a file the core could not judge (an ERROR verdict) is tried again.</summary>
    public int MaxAttempts { get; init; } = 5;

    /// <summary>On the very first run, also look at files this recent. 0 means only files from now on.</summary>
    public int InitialLookbackHours { get; init; }

    /// <summary>
    /// The program that serves the core (for example the project's python.exe). When set, the agent
    /// starts it, restarts it if it dies, and stops it on exit. Null means someone else runs the core.
    /// </summary>
    public string? CoreCommand { get; init; }

    public string[] CoreArgs { get; init; } =
        ["-m", "uvicorn", "core.api.app:create_app", "--factory", "--host", "127.0.0.1", "--port", "8765", "--no-access-log", "--no-server-header"];

    /// <summary>The core's working directory (the project folder, where its .env lives).</summary>
    public string? CoreWorkingDir { get; init; }

    /// <summary>How long a URL check waits for threat-intel providers when the agent runs the core.</summary>
    public double CoreIntelDeadlineSeconds { get; init; } = 0.5;

    /// <summary>
    /// What happens to a file the core judges MALICIOUS: "ask" (default) waits for your decision in the console,
    /// "auto" quarantines it at once, "off" never moves anything. SUSPICIOUS files are never moved.
    /// </summary>
    public string ResponseMode { get; init; } = "ask";

    /// <summary>Where the spool and state live. Null means %LOCALAPPDATA%\Mirage.</summary>
    public string? DataDir { get; init; }

    public static string DefaultDataDir => Mirage.Ipc.Endpoints.DataDir();

    public string ResolvedDataDir => string.IsNullOrWhiteSpace(DataDir) ? DefaultDataDir : DataDir;

    private static readonly JsonSerializerOptions StrictJson = new()
    {
        UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        PropertyNameCaseInsensitive = true,
    };

    public static AgentConfig Load(string path)
    {
        if (!File.Exists(path))
        {
            return new AgentConfig();
        }

        var info = new FileInfo(path);
        if (info.Length > 64 * 1024)
        {
            throw new ConfigException("agent.json is larger than 64 KiB");
        }

        try
        {
            var config = JsonSerializer.Deserialize<AgentConfig>(File.ReadAllText(path), StrictJson)
                ?? throw new ConfigException("agent.json is empty");
            config.Validate();
            return config;
        }
        catch (JsonException e)
        {
            throw new ConfigException("agent.json is not valid: " + e.Message);
        }
    }

    public void Validate()
    {
        if (!Uri.TryCreate(CoreUrl, UriKind.Absolute, out var uri) || !CoreHttp.IsLoopbackUrl(uri))
        {
            throw new ConfigException("CoreUrl must be an http URL on this machine (127.0.0.1, [::1] or localhost)");
        }

        Range(StableMillis, 10, 60_000, nameof(StableMillis));
        Range(GiveUpSeconds, 1, 86_400, nameof(GiveUpSeconds));
        Range(TickMillis, 5, 10_000, nameof(TickMillis));
        Range(MaxInspectBytes, 0, 64L * 1024 * 1024, nameof(MaxInspectBytes));
        Range(WatcherBufferBytes, 4096, 1024 * 1024, nameof(WatcherBufferBytes));
        Range(MaxPendingPaths, 1, 1_000_000, nameof(MaxPendingPaths));
        Range(MaxSpoolRecords, 1, 1_000_000, nameof(MaxSpoolRecords));
        Range(MaxKnownIds, 1, 10_000_000, nameof(MaxKnownIds));
        Range(MaxRescanFiles, 1, 1_000_000, nameof(MaxRescanFiles));
        Range(MaxAttempts, 1, 100, nameof(MaxAttempts));
        if (ResponseMode is not ("ask" or "auto" or "off"))
        {
            throw new ConfigException("ResponseMode must be ask, auto or off");
        }

        Range(RetryBaseMillis, 1, 600_000, nameof(RetryBaseMillis));
        Range(RetryMaxMillis, RetryBaseMillis, 3_600_000, nameof(RetryMaxMillis));
        Range(InitialLookbackHours, 0, 24 * 365, nameof(InitialLookbackHours));
        if (CoreCommand is not null && (!Path.IsPathRooted(CoreCommand) || CoreWorkingDir is null || !Path.IsPathRooted(CoreWorkingDir)))
        {
            throw new ConfigException("CoreCommand and CoreWorkingDir must be full paths");
        }

        for (var i = 0; i < CoreArgs.Length; i++)
        {
            // the core carries the user's token and sees every URL and file: it may only listen on this machine
            var host = CoreArgs[i] == "--host" && i + 1 < CoreArgs.Length ? CoreArgs[i + 1]
                : CoreArgs[i].StartsWith("--host=", StringComparison.Ordinal) ? CoreArgs[i][7..] : null;
            if (host is not null && host is not ("127.0.0.1" or "localhost" or "::1"))
            {
                throw new ConfigException("CoreArgs: --host must be 127.0.0.1, localhost or ::1");
            }
        }

        if (CoreIntelDeadlineSeconds is < 0.05 or > 30)
        {
            throw new ConfigException("CoreIntelDeadlineSeconds must be between 0.05 and 30");
        }

        foreach (var folder in WatchFolders)
        {
            if (string.IsNullOrWhiteSpace(folder) || !Path.IsPathRooted(folder))
            {
                throw new ConfigException("every WatchFolders entry must be a full path");
            }
        }
    }

    private static void Range(long value, long min, long max, string name)
    {
        if (value < min || value > max)
        {
            throw new ConfigException($"{name} must be between {min} and {max}");
        }
    }
}
