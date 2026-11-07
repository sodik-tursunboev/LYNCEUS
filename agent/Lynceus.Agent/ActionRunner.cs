using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace Lynceus.Agent;

/// <summary>
/// Which local file each proposed response is about. The core never has paths; the agent keeps this
/// small table (current user only) until the response is finished. Bounded: the oldest entries go first.
/// </summary>
public sealed class FlaggedStore
{
    private const int Limit = 500;
    private static readonly JsonSerializerOptions Json = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };
    private readonly object gate = new();
    private readonly string path;
    private readonly List<Entry> entries = [];

    public FlaggedStore(string path)
    {
        this.path = path;
        try
        {
            entries = JsonSerializer.Deserialize<List<Entry>>(File.ReadAllText(path), Json) ?? [];
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
        {
            entries = [];
        }
    }

    public void Add(Guid actionId, string filePath, string sha256, long size, long modifiedTicks)
    {
        lock (gate)
        {
            if (entries.Exists(e => e.Id == actionId.ToString("D")))
            {
                return;
            }

            entries.Add(new Entry { Id = actionId.ToString("D"), PathB64 = PathCodec.Encode(filePath), Sha256 = sha256, Size = size, Mtime = modifiedTicks });
            if (entries.Count > Limit)
            {
                entries.RemoveRange(0, entries.Count - Limit);
            }

            Save();
        }
    }

    public (string Path, string Sha256, long Size, long ModifiedTicks)? Find(Guid actionId)
    {
        lock (gate)
        {
            var e = entries.Find(x => x.Id == actionId.ToString("D"));
            return e is not null && PathCodec.Decode(e.PathB64) is { } p ? (p, e.Sha256, e.Size, e.Mtime) : null;
        }
    }

    /// <summary>True the first time it is called for this action (so a notification is shown once).</summary>
    public bool FirstAnnouncement(Guid actionId, string stage)
    {
        lock (gate)
        {
            var e = entries.Find(x => x.Id == actionId.ToString("D"));
            if (e is null || e.Announced.Contains(stage))
            {
                return false;
            }

            e.Announced.Add(stage);
            Save();
            return true;
        }
    }

    private void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(entries, Json));
        File.Move(temp, path, overwrite: true);
    }

    private sealed class Entry
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;

        [JsonPropertyName("p")]
        public string PathB64 { get; set; } = string.Empty;

        [JsonPropertyName("sha")]
        public string Sha256 { get; set; } = string.Empty;

        [JsonPropertyName("size")]
        public long Size { get; set; }

        [JsonPropertyName("mtime")]
        public long Mtime { get; set; }

        [JsonPropertyName("said")]
        public List<string> Announced { get; set; } = [];
    }
}

/// <summary>
/// Carries out what the core has decided, and nothing else. Every few seconds it asks for actions that are
/// waiting: an APPROVED one is quarantined and reported; a RESTORE_REQUESTED one is restored and reported;
/// a PENDING one is approved only in "auto" mode (as the policy) and otherwise announced once and left for
/// you. It never acts on an action the core has not approved, and every step is safe to repeat: the report
/// back is retried until the core has it, and the store treats a second attempt as already done.
/// </summary>
public sealed class ActionRunner(
    CoreClient core,
    FlaggedStore flagged,
    QuarantineStore quarantine,
    string mode,
    Action<(string Title, string Body)> notify,
    Action<string, long, long> restored,
    ILogger log)
{
    public async Task PollOnceAsync(CancellationToken ct)
    {
        // "off" never moves a file into quarantine, but a restore is something you asked for: it always runs.
        var wanted = mode == "off" ? "RESTORE_REQUESTED" : "PENDING,APPROVED,RESTORE_REQUESTED";
        var (status, actions) = await core.ListActionsAsync(wanted, ct).ConfigureAwait(false);
        if (status != CoreStatus.Ok)
        {
            return;
        }

        foreach (var action in actions.OrderBy(a => a.State))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                switch (action.State)
                {
                    case "PENDING" when mode != "off":
                        await HandlePendingAsync(action, ct).ConfigureAwait(false);
                        break;
                    case "APPROVED" when mode != "off":
                        await QuarantineAsync(action, ct).ConfigureAwait(false);
                        break;
                    case "RESTORE_REQUESTED":
                        await RestoreAsync(action, ct).ConfigureAwait(false);
                        break;
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception e)
            {
                // One action that cannot be handled must not stop the others, restores included, and the
                // core must be told: a stated failure, never silence.
                log.LogWarning("action {Id} could not be handled ({Type})", Short(action), e.GetType().Name);
                var outcome = action.State == "RESTORE_REQUESTED" ? "restore_failed" : action.State == "APPROVED" ? "failed" : null;
                if (outcome is not null)
                {
                    await core.ReportAsync(action.Id, outcome, "io", ct).ConfigureAwait(false);
                }
            }
        }
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
                log.LogWarning("the response step failed ({Type})", e.GetType().Name);
                await Task.Delay(every, CancellationToken.None).ConfigureAwait(false);
            }
        }
    }

    private async Task HandlePendingAsync(ActionInfo action, CancellationToken ct)
    {
        if (flagged.Find(action.Id) is null)
        {
            return; // not one of this agent's files
        }

        if (mode == "auto")
        {
            if (await core.ApproveAsync(action.Id, ct).ConfigureAwait(false) == CoreStatus.Ok)
            {
                log.LogInformation("action {Id} approved by policy", Short(action));
            }

            return;
        }

        if (flagged.FirstAnnouncement(action.Id, "pending"))
        {
            notify(("Lynceus: a dangerous file is waiting for your decision", "Open the Lynceus console to quarantine it or leave it. Nothing has been moved."));
        }
    }

    private async Task QuarantineAsync(ActionInfo action, CancellationToken ct)
    {
        if (flagged.Find(action.Id) is not { } file)
        {
            await core.ReportAsync(action.Id, "failed", "unknown_file", ct).ConfigureAwait(false);
            return;
        }

        var result = quarantine.Quarantine(action.Id.ToString("D"), file.Path, file.Sha256);
        if (result.Ok)
        {
            if (await core.ReportAsync(action.Id, "applied", null, ct).ConfigureAwait(false) == CoreStatus.Ok
                && flagged.FirstAnnouncement(action.Id, "applied"))
            {
                notify(("Lynceus: file quarantined", "It was moved to Lynceus's quarantine folder. You can restore it from the console."));
            }

            return;
        }

        if (result.Reason == "remove_failed")
        {
            return; // both copies exist; the next poll finishes the job
        }

        log.LogWarning("quarantine of {Id} failed: {Reason}", Short(action), result.Reason);
        if (await core.ReportAsync(action.Id, "failed", result.Reason, ct).ConfigureAwait(false) == CoreStatus.Ok
            && flagged.FirstAnnouncement(action.Id, "failed"))
        {
            notify(("Lynceus: could not quarantine the file", $"The file was left where it is ({result.Reason.Replace('_', ' ')})."));
        }
    }

    private async Task RestoreAsync(ActionInfo action, CancellationToken ct)
    {
        var result = quarantine.Restore(action.Id.ToString("D"));
        if (result.Ok)
        {
            if (result.RestoredPath is { } where && result.Size >= 0)
            {
                restored(where, result.Size, result.ModifiedTicks); // do not judge Lynceus's own restore as a new download
            }

            if (await core.ReportAsync(action.Id, "restored", null, ct).ConfigureAwait(false) == CoreStatus.Ok
                && flagged.FirstAnnouncement(action.Id, "restored"))
            {
                var message = result.Reason.StartsWith("renamed", StringComparison.Ordinal) ? "It was put back under a new name because the old one is in use." : "It is back where it was.";
                notify(("Lynceus: file restored", result.Reason.EndsWith("unmarked", StringComparison.Ordinal) ? message + " Windows could not re-apply its download mark." : message));
            }

            return;
        }

        log.LogWarning("restore of {Id} failed: {Reason}", Short(action), result.Reason);
        await core.ReportAsync(action.Id, "restore_failed", result.Reason, ct).ConfigureAwait(false);
    }

    private static string Short(ActionInfo action) => action.Id.ToString("N")[..8];
}
