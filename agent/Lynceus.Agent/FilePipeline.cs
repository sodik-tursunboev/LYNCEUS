using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Lynceus.Agent;

/// <summary>A file the core has judged. The name and path are for the local notification only.</summary>
public sealed record FileOutcome(FileEvent Event, string Sha256, string? OriginHost, string? Magic, FileVerdict Verdict);

public sealed record PipelineStats(
    long Observed, long Judged, long Errors, long GaveUp, long Vanished, long Skipped, long PendingOverflow,
    int WaitingForQuiet, int WaitingForCore, long Dropped);

/// <summary>
/// Watch folders, decide when a downloaded file is finished, queue it, and have the core judge it.
/// Events can be lost (buffer overflow, a full table, a restart), so every loss triggers a re-scan
/// and a re-scan is cheap: an event already seen is skipped without opening the file. The agent
/// never moves, changes or deletes a file; the most it does is read it once.
/// </summary>
public sealed class FilePipeline : IDisposable
{
    private static readonly string[] TemporaryExtensions =
        [".crdownload", ".tmp", ".part", ".partial", ".download", ".opdownload", ".!ut", ".bc!"];

    private static readonly TimeSpan CheckpointMargin = TimeSpan.FromMinutes(2);

    private readonly AgentConfig config;
    private readonly string[] folders;
    private readonly Spool spool;
    private readonly CoreClient core;
    private readonly TimeProvider time;
    private readonly ILogger log;
    private readonly string statePath;
    private readonly ConcurrentDictionary<string, Pending> pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, FileSystemWatcher?> watchers = [];
    private readonly Dictionary<string, int> attempts = [];
    private readonly object watcherGate = new();
    private DateTimeOffset checkpoint;
    private volatile bool rescanWanted;
    private bool started;
    private DateTimeOffset coreDownUntil;
    private TimeSpan coreDelay;
    private bool coreWasDown;
    private long observed, judged, errors, gaveUp, vanished, skipped, pendingOverflow;

    public FilePipeline(AgentConfig config, IEnumerable<string> folders, Spool spool, CoreClient core, ILogger log, TimeProvider? time = null)
    {
        this.config = config;
        this.folders = [.. folders.Select(f => Path.GetFullPath(f).TrimEnd('\\', '/'))];
        this.spool = spool;
        this.core = core;
        this.log = log;
        this.time = time ?? TimeProvider.System;
        statePath = Path.Combine(config.ResolvedDataDir, "state.json");
        coreDelay = TimeSpan.FromMilliseconds(config.RetryBaseMillis);
    }

    /// <summary>Raised on the delivery thread for every file the core judged.</summary>
    public event Action<FileOutcome>? Judged;

    public PipelineStats Stats => new(
        Interlocked.Read(ref observed), Interlocked.Read(ref judged), Interlocked.Read(ref errors), Interlocked.Read(ref gaveUp),
        Interlocked.Read(ref vanished), Interlocked.Read(ref skipped), Interlocked.Read(ref pendingOverflow),
        pending.Count, spool.Stats.Pending, spool.Stats.Dropped);

    public static bool IsTemporaryName(string name) =>
        name.Contains(':', StringComparison.Ordinal)
        || name.StartsWith("~$", StringComparison.Ordinal)
        || name.EndsWith('~')
        || TemporaryExtensions.Contains(Path.GetExtension(name), StringComparer.OrdinalIgnoreCase);

    public static string EventId(string path, long size, long modifiedTicks)
    {
        var text = $"{path.ToLowerInvariant()}|{size}|{modifiedTicks}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)))[..32].ToLowerInvariant();
    }

    /// <summary>A file Lynceus itself put back (restore): do not judge it again as if it were new.</summary>
    public void Suppress(string path, long size, long modifiedTicks) => spool.MarkKnown(EventId(Path.GetFullPath(path), size, modifiedTicks));

    // ---- life cycle -------------------------------------------------------------------------

    /// <summary>Start watching, then look back over what the previous run may not have seen.</summary>
    public void Start()
    {
        if (started)
        {
            return;
        }

        started = true;
        checkpoint = LoadCheckpoint();
        if (!File.Exists(statePath))
        {
            WriteCheckpoint(); // so a restart soon after the first start still looks back to here
        }

        foreach (var folder in folders)
        {
            EnsureWatcher(folder);
        }

        rescanWanted = true;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        Start();
        try
        {
            await Task.WhenAll(Loop(ObserveLoopBody, ct), Loop(DeliverLoopBody, ct), Loop(MaintenanceBody, ct)).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // stopping
        }
        finally
        {
            SaveCheckpoint();
        }
    }

    public void Dispose()
    {
        lock (watcherGate)
        {
            foreach (var watcher in watchers.Values)
            {
                watcher?.Dispose();
            }

            watchers.Clear();
        }
    }

    private async Task Loop(Func<CancellationToken, Task<TimeSpan>> body, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TimeSpan wait;
            try
            {
                wait = await body(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception e)
            {
                log.LogError("a pipeline step failed ({Type}); continuing", e.GetType().Name);
                wait = TimeSpan.FromSeconds(1);
            }

            if (wait > TimeSpan.Zero)
            {
                await Task.Delay(wait, time, ct).ConfigureAwait(false);
            }
        }
    }

    private Task<TimeSpan> ObserveLoopBody(CancellationToken ct)
    {
        ObserveTick();
        return Task.FromResult(TimeSpan.FromMilliseconds(config.TickMillis));
    }

    private async Task<TimeSpan> DeliverLoopBody(CancellationToken ct) =>
        await DeliverOneAsync(ct).ConfigureAwait(false) ? TimeSpan.Zero : TimeSpan.FromMilliseconds(config.TickMillis);

    private Task<TimeSpan> MaintenanceBody(CancellationToken ct)
    {
        foreach (var folder in folders)
        {
            EnsureWatcher(folder);
        }

        SaveCheckpoint();
        return Task.FromResult(TimeSpan.FromSeconds(30));
    }

    // ---- watching -----------------------------------------------------------------------------

    private void EnsureWatcher(string folder)
    {
        lock (watcherGate)
        {
            if (watchers.TryGetValue(folder, out var existing) && existing is not null)
            {
                return;
            }

            watchers[folder] = null;
            if (!Directory.Exists(folder))
            {
                return;
            }

            try
            {
                var watcher = new FileSystemWatcher(folder)
                {
                    IncludeSubdirectories = config.IncludeSubfolders,
                    InternalBufferSize = config.WatcherBufferBytes,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
                };
                watcher.Created += (_, a) => Touch(a.FullPath);
                watcher.Changed += (_, a) => Touch(a.FullPath);
                watcher.Renamed += (_, a) => Touch(a.FullPath);
                watcher.Error += (_, a) => OnWatcherError(folder, a.GetException());
                watcher.EnableRaisingEvents = true;
                watchers[folder] = watcher;
                rescanWanted = true; // anything that happened while no watcher ran
            }
            catch (Exception e) when (e is ArgumentException or IOException or UnauthorizedAccessException or PlatformNotSupportedException)
            {
                log.LogWarning("could not watch a folder ({Type}); will retry", e.GetType().Name);
            }
        }
    }

    internal void OnWatcherError(string folder, Exception error)
    {
        rescanWanted = true;
        log.LogWarning("the folder watcher reported {Type}; a re-scan is scheduled", error.GetType().Name);
        if (error is not InternalBufferOverflowException)
        {
            lock (watcherGate)
            {
                if (watchers.TryGetValue(folder, out var broken))
                {
                    broken?.Dispose();
                    watchers[folder] = null;
                }
            }
        }
    }

    /// <summary>Ask for a full re-scan from the last safe point (used by tests and by loss handling).</summary>
    internal void RequestRescan() => rescanWanted = true;

    // ---- candidates -----------------------------------------------------------------------------

    /// <summary>A path changed (or was found by a re-scan). Cheap, thread-safe, and safe to call twice.</summary>
    internal void Touch(string path)
    {
        string full;
        try
        {
            full = Path.GetFullPath(path);
        }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return;
        }

        if (IsTemporaryName(Path.GetFileName(full)))
        {
            return;
        }

        var now = time.GetUtcNow();
        if (pending.TryGetValue(full, out var existing))
        {
            Volatile.Write(ref existing.LastEventTicks, now.Ticks);
            return;
        }

        var entry = new Pending(now);
        var (size, modified) = Sample(full);
        if (size >= 0 && spool.Knows(EventId(full, size, modified)))
        {
            return; // seen before, unchanged
        }

        if (pending.Count >= config.MaxPendingPaths)
        {
            rescanWanted = true;
            Interlocked.Increment(ref pendingOverflow);
            return;
        }

        entry.Size = size;
        entry.Modified = modified;
        pending.TryAdd(full, entry);
    }

    private static (long Size, long Modified) Sample(string path)
    {
        try
        {
            var info = new FileInfo(path);
            return info.Exists ? (info.Length, info.LastWriteTimeUtc.Ticks) : (-1, 0);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return (-1, 0);
        }
    }

    /// <summary>Move candidates that have been quiet, unchanged and openable into the spool.</summary>
    internal void ObserveTick()
    {
        if (rescanWanted && pending.Count < config.MaxPendingPaths / 2)
        {
            rescanWanted = false;
            Rescan(checkpoint);
        }

        var now = time.GetUtcNow();
        var quiet = TimeSpan.FromMilliseconds(config.StableMillis);
        foreach (var (path, entry) in pending)
        {
            if (now.Ticks - Volatile.Read(ref entry.LastEventTicks) < quiet.Ticks)
            {
                continue;
            }

            var (size, modified) = Sample(path);
            if (size < 0)
            {
                pending.TryRemove(path, out _);
                continue;
            }

            if (size != entry.Size || modified != entry.Modified)
            {
                entry.Size = size;
                entry.Modified = modified;
                Volatile.Write(ref entry.LastEventTicks, now.Ticks);
                continue; // still changing
            }

            switch (Admit(path))
            {
                case Admission.Skip:
                    Interlocked.Increment(ref skipped);
                    pending.TryRemove(path, out _);
                    break;
                case Admission.Wait:
                    entry.FailingSince ??= now;
                    if (now - entry.FailingSince > TimeSpan.FromSeconds(config.GiveUpSeconds))
                    {
                        Interlocked.Increment(ref gaveUp);
                        log.LogWarning("gave up on a file that stayed locked");
                        pending.TryRemove(path, out _);
                    }

                    break;
                default:
                    var id = EventId(path, size, modified);
                    var added = spool.TryAdd(new FileEvent(id, path, Path.GetFileName(path), size, modified, now));
                    pending.TryRemove(path, out _);
                    if (added)
                    {
                        Interlocked.Increment(ref observed);
                    }

                    break;
            }
        }
    }

    private enum Admission
    {
        Ready,
        Wait,
        Skip,
    }

    private Admission Admit(string path)
    {
        try
        {
            if (ShouldNotRead(path))
            {
                return Admission.Skip;
            }

            using var probe = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 1);
            return Admission.Ready;
        }
        catch (IOException e) when (IsBlockedBySecurityProduct(e))
        {
            log.LogInformation("another security product blocked access to a file; not judged here");
            return Admission.Skip;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return Admission.Wait;
        }
    }

    /// <summary>ERROR_VIRUS_INFECTED (225) and ERROR_VIRUS_DELETED (226): the antivirus already acted.</summary>
    private static bool IsBlockedBySecurityProduct(IOException e) => (e.HResult & 0xFFFF) is 225 or 226;

    /// <summary>Links are not followed, and cloud placeholders are not downloaded just to be looked at.</summary>
    private bool ShouldNotRead(string path)
    {
        var info = new FileInfo(path);
        const FileAttributes recallOnOpen = (FileAttributes)0x40000;
        const FileAttributes recallOnDataAccess = (FileAttributes)0x400000;
        var offline = FileAttributes.Offline | recallOnOpen | recallOnDataAccess;
        if (info.Attributes.HasFlag(FileAttributes.Directory) || (info.Attributes & offline) != 0 || info.LinkTarget is not null)
        {
            return true;
        }

        var root = folders.FirstOrDefault(f => path.StartsWith(f + "\\", StringComparison.OrdinalIgnoreCase));
        for (var dir = Path.GetDirectoryName(path); root is not null && dir is not null && dir.Length > root.Length; dir = Path.GetDirectoryName(dir))
        {
            if (new DirectoryInfo(dir).LinkTarget is not null)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Look for files newer than <paramref name="since"/>; ones already seen cost a stat each.</summary>
    internal void Rescan(DateTimeOffset since)
    {
        var found = new List<FileInfo>();
        foreach (var folder in folders)
        {
            foreach (var file in Walk(folder))
            {
                if (!IsTemporaryName(file.Name) && (file.LastWriteTimeUtc >= since || file.CreationTimeUtc >= since))
                {
                    found.Add(file);
                }
            }
        }

        if (found.Count > config.MaxRescanFiles)
        {
            log.LogWarning("a re-scan found {Count} recent files; looking at the newest {Max}", found.Count, config.MaxRescanFiles);
            found = [.. found.OrderByDescending(f => f.LastWriteTimeUtc).Take(config.MaxRescanFiles)];
        }

        foreach (var file in found)
        {
            Touch(file.FullName);
        }
    }

    private IEnumerable<FileInfo> Walk(string root)
    {
        var stack = new Stack<(string Dir, int Depth)>();
        stack.Push((root, 0));
        while (stack.Count > 0)
        {
            var (dir, depth) = stack.Pop();
            List<FileSystemInfo> entries;
            try
            {
                entries = [.. new DirectoryInfo(dir).EnumerateFileSystemInfos("*", new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = 0 })];
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var entry in entries)
            {
                if (entry is DirectoryInfo sub)
                {
                    if (config.IncludeSubfolders && depth < 4 && sub.LinkTarget is null)
                    {
                        stack.Push((sub.FullName, depth + 1));
                    }
                }
                else if (entry is FileInfo file)
                {
                    yield return file;
                }
            }
        }
    }

    // ---- state ----------------------------------------------------------------------------------

    private DateTimeOffset LoadCheckpoint()
    {
        try
        {
            if (File.Exists(statePath))
            {
                using var document = JsonDocument.Parse(File.ReadAllBytes(statePath));
                if (document.RootElement.TryGetProperty("checkpoint", out var value) && value.TryGetDateTimeOffset(out var at))
                {
                    return at;
                }
            }
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
        {
            log.LogWarning("the agent state file could not be read ({Type}); looking back one day", e.GetType().Name);
            return time.GetUtcNow().AddDays(-1);
        }

        return time.GetUtcNow().AddHours(-config.InitialLookbackHours);
    }

    /// <summary>
    /// Everything up to the checkpoint is known to have been seen. It only moves forward when no
    /// loss is pending, and never past a file still waiting to be finished.
    /// </summary>
    internal void SaveCheckpoint()
    {
        if (rescanWanted)
        {
            return;
        }

        var next = time.GetUtcNow() - CheckpointMargin;
        foreach (var entry in pending.Values)
        {
            var from = entry.FirstSeen - CheckpointMargin;
            next = from < next ? from : next;
        }

        if (next <= checkpoint)
        {
            return;
        }

        checkpoint = next;
        WriteCheckpoint();
    }

    private void WriteCheckpoint()
    {
        try
        {
            Directory.CreateDirectory(config.ResolvedDataDir);
            var temp = statePath + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(new { checkpoint }), new UTF8Encoding(false));
            File.Move(temp, statePath, overwrite: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            log.LogWarning("the agent state file could not be written ({Type})", e.GetType().Name);
        }
    }

    // ---- delivery ---------------------------------------------------------------------------------

    private enum ReadState
    {
        Ok,
        Vanished,
        Skipped,
        Unstable,
        Busy,
    }

    private sealed record Snapshot(string Sha256, long Size, string? Magic, string? Host, byte[]? Data);

    /// <summary>Judge the oldest waiting file. Returns false when there was nothing to do right now.</summary>
    internal async Task<bool> DeliverOneAsync(CancellationToken ct)
    {
        var now = time.GetUtcNow();
        if (now < coreDownUntil || spool.NextDue(now) is not { } e)
        {
            return false;
        }

        switch (ReadFile(e, out var snapshot))
        {
            case ReadState.Vanished:
                Interlocked.Increment(ref vanished);
                spool.Complete(e.Id, "vanished");
                return true;
            case ReadState.Skipped:
                Interlocked.Increment(ref skipped);
                spool.Complete(e.Id, "skipped");
                return true;
            case ReadState.Unstable or ReadState.Busy:
                TryLater(e, "the file was changing or locked");
                return true;
        }

        var file = snapshot!;
        var result = file.Data is not null
            ? await core.AnalyzeAsync(e.Name, file.Sha256, file.Host, file.Data, ct, e.Id).ConfigureAwait(false)
            : await core.CheckAsync(e.Name, file.Size, file.Sha256, file.Magic, file.Host, ct, e.Id).ConfigureAwait(false);
        if (result.Status == CoreStatus.TooLarge && file.Data is not null)
        {
            result = await core.CheckAsync(e.Name, file.Size, file.Sha256, file.Magic, file.Host, ct, e.Id).ConfigureAwait(false);
        }

        switch (result.Status)
        {
            case CoreStatus.Ok:
                CoreIsUp();
                Finish(e, file, result.Verdict!);
                return true;
            case CoreStatus.Unavailable or CoreStatus.Unauthorized:
                CoreIsDown(result);
                return false;
            default:
                Interlocked.Increment(ref errors);
                log.LogError("the core refused file {Id}: {Detail}", e.Id[..8], result.Detail);
                spool.Complete(e.Id, "rejected");
                return true;
        }
    }

    private ReadState ReadFile(FileEvent e, out Snapshot? snapshot)
    {
        snapshot = null;
        try
        {
            if (!new FileInfo(e.Path).Exists)
            {
                return ReadState.Vanished;
            }

            if (ShouldNotRead(e.Path))
            {
                return ReadState.Skipped;
            }

            using var stream = new FileStream(e.Path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 1, FileOptions.SequentialScan);
            var length = stream.Length;
            var host = MarkOfTheWeb.OriginHost(e.Path);
            if (length <= config.MaxInspectBytes)
            {
                var data = new byte[length];
                stream.ReadExactly(data);
                if (stream.ReadByte() != -1 || stream.Length != length)
                {
                    return ReadState.Unstable;
                }

                var hash = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
                snapshot = new Snapshot(hash, length, FileSignatures.Detect(data.AsSpan(0, Math.Min(data.Length, FileSignatures.HeadBytes))), host, data);
                return ReadState.Ok;
            }

            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var head = new byte[FileSignatures.HeadBytes];
            var headLength = 0;
            var buffer = new byte[81920];
            long total = 0;
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                sha.AppendData(buffer, 0, read);
                var take = Math.Min(read, head.Length - headLength);
                Array.Copy(buffer, 0, head, headLength, take);
                headLength += take;
                total += read;
            }

            if (total != length || stream.Length != length)
            {
                return ReadState.Unstable;
            }

            snapshot = new Snapshot(Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant(), length, FileSignatures.Detect(head.AsSpan(0, headLength)), host, null);
            return ReadState.Ok;
        }
        catch (Exception e2) when (e2 is FileNotFoundException or DirectoryNotFoundException)
        {
            return ReadState.Vanished;
        }
        catch (EndOfStreamException)
        {
            return ReadState.Unstable; // shrank while being read
        }
        catch (IOException e2) when (IsBlockedBySecurityProduct(e2))
        {
            return ReadState.Skipped;
        }
        catch (Exception e2) when (e2 is IOException or UnauthorizedAccessException)
        {
            return ReadState.Busy;
        }
    }

    private void Finish(FileEvent e, Snapshot file, FileVerdict verdict)
    {
        if (verdict.State == "ERROR" && TryLater(e, "the core could not judge the file"))
        {
            return;
        }

        attempts.Remove(e.Id);
        spool.Complete(e.Id, verdict.State);
        Interlocked.Increment(ref judged);
        log.LogInformation("file {Id} judged {State}", e.Id[..8], verdict.State);
        try
        {
            Judged?.Invoke(new FileOutcome(e, file.Sha256, file.Host, file.Magic, verdict));
        }
        catch (Exception ex)
        {
            log.LogError("a verdict handler failed ({Type})", ex.GetType().Name);
        }
    }

    /// <summary>Put the event back for another try, or give up after MaxAttempts and say so.</summary>
    private bool TryLater(FileEvent e, string why)
    {
        var count = attempts.GetValueOrDefault(e.Id) + 1;
        if (count >= config.MaxAttempts)
        {
            attempts.Remove(e.Id);
            Interlocked.Increment(ref gaveUp);
            log.LogWarning("gave up on file {Id} after {Count} tries: {Why}", e.Id[..8], count, why);
            spool.Complete(e.Id, "gave_up");
            return false;
        }

        attempts[e.Id] = count;
        spool.Defer(e.Id, time.GetUtcNow() + (TimeSpan.FromMilliseconds(config.RetryBaseMillis) * count));
        return true;
    }

    private void CoreIsDown(CoreResult result)
    {
        if (!coreWasDown)
        {
            log.LogWarning("the core is not answering ({Detail}); waiting files are kept", result.Detail);
        }

        coreWasDown = true;
        coreDownUntil = time.GetUtcNow() + coreDelay;
        coreDelay = TimeSpan.FromTicks(Math.Min(coreDelay.Ticks * 2, TimeSpan.FromMilliseconds(config.RetryMaxMillis).Ticks));
    }

    private void CoreIsUp()
    {
        if (coreWasDown)
        {
            log.LogInformation("the core is answering again");
        }

        coreWasDown = false;
        coreDelay = TimeSpan.FromMilliseconds(config.RetryBaseMillis);
    }

    private sealed class Pending(DateTimeOffset seen)
    {
        public DateTimeOffset FirstSeen { get; } = seen;

        public long LastEventTicks = seen.Ticks;

        public long Size = -1;

        public long Modified;

        public DateTimeOffset? FailingSince { get; set; }
    }
}
