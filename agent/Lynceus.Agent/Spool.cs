using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Lynceus.Agent;

/// <summary>One new file waiting for a verdict. The path is local-only: it never goes to the core or a log.</summary>
public sealed record FileEvent(string Id, string Path, string Name, long Size, long ModifiedTicks, DateTimeOffset Seen);

public sealed record SpoolStats(int Pending, long Dropped, long Corrupt);

/// <summary>
/// The agent's queue of files not yet judged: an append-only JSON-lines file, at-least-once and
/// idempotent (the same path, size and modified time is one event, however often it is seen).
/// It is bounded: when full, the oldest waiting event is dropped and the loss is counted and kept
/// across restarts. It holds no URLs, no hashes of content and no file contents.
/// </summary>
public sealed class Spool
{
    private const int CompactAfterLines = 5000;

    private static readonly JsonSerializerOptions Json = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private readonly object gate = new();
    private readonly string path;
    private readonly int maxRecords;
    private readonly int maxKnown;
    private readonly TimeProvider time;
    private readonly List<FileEvent> pending = [];
    private readonly Dictionary<string, DateTimeOffset> notBefore = [];
    private readonly HashSet<string> known = [];
    private readonly Queue<string> knownOrder = new();
    private long dropped;
    private long corrupt;
    private int linesSinceCompact;

    public Spool(string path, int maxRecords, int maxKnown, TimeProvider? time = null)
    {
        this.path = path;
        this.maxRecords = maxRecords;
        this.maxKnown = maxKnown;
        this.time = time ?? TimeProvider.System;
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path))!);
        Load();
        Compact();
    }

    public SpoolStats Stats
    {
        get
        {
            lock (gate)
            {
                return new SpoolStats(pending.Count, dropped, corrupt);
            }
        }
    }

    /// <summary>False when this event was seen before (waiting, judged, or dropped).</summary>
    public bool TryAdd(FileEvent e)
    {
        lock (gate)
        {
            if (known.Contains(e.Id))
            {
                return false;
            }

            if (pending.Count >= maxRecords)
            {
                var oldest = pending[0];
                pending.RemoveAt(0);
                notBefore.Remove(oldest.Id);
                dropped++;
                Append(new Line { T = "drop", Id = oldest.Id, At = time.GetUtcNow() }, durable: false);
                Append(new Line { T = "meta", Dropped = dropped }, durable: false);
            }

            pending.Add(e);
            Remember(e.Id);
            Append(AddLine(e), durable: true);
            return true;
        }
    }

    /// <summary>Remember an event as done without ever queueing it (a file Lynceus restored itself).</summary>
    public void MarkKnown(string id)
    {
        lock (gate)
        {
            Remember(id);
            Append(new Line { T = "done", Id = id, State = "known", At = time.GetUtcNow() }, durable: false);
        }
    }

    /// <summary>True when this event is waiting, was judged, or was dropped.</summary>
    public bool Knows(string id)
    {
        lock (gate)
        {
            return known.Contains(id);
        }
    }

    /// <summary>The oldest waiting event that may be tried now.</summary>
    public FileEvent? NextDue(DateTimeOffset now)
    {
        lock (gate)
        {
            return pending.FirstOrDefault(e => !notBefore.TryGetValue(e.Id, out var until) || until <= now);
        }
    }

    /// <summary>Try this event again no sooner than <paramref name="until"/> (kept in memory only).</summary>
    public void Defer(string id, DateTimeOffset until)
    {
        lock (gate)
        {
            notBefore[id] = until;
        }
    }

    public void Complete(string id, string outcome)
    {
        lock (gate)
        {
            if (pending.RemoveAll(e => e.Id == id) == 0)
            {
                return;
            }

            notBefore.Remove(id);
            Append(new Line { T = "done", Id = id, State = outcome, At = time.GetUtcNow() }, durable: false);
        }
    }

    public IReadOnlyList<FileEvent> Snapshot()
    {
        lock (gate)
        {
            return [.. pending];
        }
    }

    private void Remember(string id)
    {
        if (!known.Add(id))
        {
            return;
        }

        knownOrder.Enqueue(id);
        while (knownOrder.Count > maxKnown)
        {
            var old = knownOrder.Dequeue();
            if (!pending.Exists(p => p.Id == old))
            {
                known.Remove(old);
            }
            else
            {
                knownOrder.Enqueue(old);
                break;
            }
        }
    }

    private void Load()
    {
        if (!File.Exists(path))
        {
            return;
        }

        foreach (var text in File.ReadLines(path, Encoding.UTF8))
        {
            Line? line;
            try
            {
                line = JsonSerializer.Deserialize<Line>(text, Json);
            }
            catch (JsonException)
            {
                line = null;
            }

            if (line?.T is null || (line.T != "meta" && string.IsNullOrEmpty(line.Id)))
            {
                corrupt++;
                continue;
            }

            switch (line.T)
            {
                case "add" when line.P is not null && PathCodec.Decode(line.P) is { } decoded:
                    if (known.Contains(line.Id!))
                    {
                        break;
                    }

                    pending.Add(new FileEvent(line.Id!, decoded, System.IO.Path.GetFileName(decoded), line.Size, line.Mtime, line.At));
                    Remember(line.Id!);
                    break;
                case "done" or "drop":
                    pending.RemoveAll(e => e.Id == line.Id);
                    Remember(line.Id!);
                    break;
                case "meta":
                    dropped = Math.Max(dropped, line.Dropped);
                    break;
                default:
                    corrupt++;
                    break;
            }
        }
    }

    /// <summary>Rewrite the file with only what still matters, replacing it in one step.</summary>
    private void Compact()
    {
        var temp = path + ".tmp";
        using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
        using (var writer = new StreamWriter(stream, new UTF8Encoding(false)) { NewLine = "\n" })
        {
            var live = pending.Select(p => p.Id).ToHashSet();
            writer.WriteLine(JsonSerializer.Serialize(new Line { T = "meta", Dropped = dropped }, Json));
            foreach (var id in knownOrder.Where(id => !live.Contains(id)))
            {
                writer.WriteLine(JsonSerializer.Serialize(new Line { T = "done", Id = id, State = "known" }, Json));
            }

            foreach (var e in pending)
            {
                writer.WriteLine(JsonSerializer.Serialize(
                    AddLine(e),
                    Json));
            }

            writer.Flush();
            stream.Flush(flushToDisk: true);
        }

        File.Move(temp, path, overwrite: true);
        linesSinceCompact = 0;
    }

    private void Append(Line line, bool durable)
    {
        if (linesSinceCompact >= CompactAfterLines)
        {
            Compact();
        }

        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(line, Json) + "\n");
        using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
        stream.Write(bytes);
        stream.Flush(flushToDisk: durable);
        linesSinceCompact++;
    }

    /// <summary>The path as its exact UTF-16 code units in base64: NTFS allows names JSON cannot hold.</summary>
    private static Line AddLine(FileEvent e) => new()
    {
        T = "add",
        Id = e.Id,
        P = PathCodec.Encode(e.Path),
        Size = e.Size,
        Mtime = e.ModifiedTicks,
        At = e.Seen,
    };

    private sealed class Line
    {
        [JsonPropertyName("t")]
        public string? T { get; set; }

        [JsonPropertyName("id")]
        public string? Id { get; set; }

        [JsonPropertyName("p")]
        public string? P { get; set; }

        [JsonPropertyName("size")]
        public long Size { get; set; }

        [JsonPropertyName("mtime")]
        public long Mtime { get; set; }

        [JsonPropertyName("at")]
        public DateTimeOffset At { get; set; }

        [JsonPropertyName("state")]
        public string? State { get; set; }

        [JsonPropertyName("dropped")]
        public long Dropped { get; set; }
    }
}
