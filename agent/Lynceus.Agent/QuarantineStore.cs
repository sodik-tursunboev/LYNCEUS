using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Lynceus.Agent;

/// <summary>The file-system operations quarantine needs, so tests can make any one of them fail.</summary>
public class RealFileSystem
{
    public virtual bool SameVolume(string a, string b) =>
        string.Equals(Path.GetPathRoot(Path.GetFullPath(a)), Path.GetPathRoot(Path.GetFullPath(b)), StringComparison.OrdinalIgnoreCase);

    /// <summary>Readers and renames are allowed, writers are not: what is hashed is what is moved.</summary>
    public virtual FileStream OpenRead(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 81920, FileOptions.SequentialScan);

    /// <summary>Never overwrites: a name that exists is an error.</summary>
    public virtual FileStream CreateNew(string path) => new(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920);

    public virtual void Move(string source, string destination) => File.Move(source, destination, overwrite: false);

    /// <summary>Removes a file this program made (a half-written copy or temp). Never a user's file.</summary>
    public virtual void Delete(string path) => File.Delete(path);

    /// <summary>
    /// The only removal of a user's file in the agent (see <see cref="QuarantineStore"/>). The file is opened
    /// once, with nobody else allowed to write, rename or delete it; its hash is checked through that handle and
    /// the same handle is marked for deletion. The name cannot be pointed at another file in between. False
    /// (nothing deleted) when the content is not the verified one or the path is a link.
    /// </summary>
    public virtual bool DeleteIfSame(string path, string sha256, Action beforeDelete)
    {
        using var handle = NativeDelete.OpenForVerifiedDelete(path);
        if (NativeDelete.IsReparsePoint(handle))
        {
            return false;
        }

        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[81920];
        long offset = 0;
        int read;
        while ((read = RandomAccess.Read(handle, buffer, offset)) > 0)
        {
            sha.AppendData(buffer, 0, read);
            offset += read;
        }

        if (!string.Equals(Convert.ToHexString(sha.GetHashAndReset()), sha256, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        beforeDelete();
        NativeDelete.MarkForDeletion(handle); // deleted when this handle closes
        return true;
    }

    public virtual bool Exists(string path) => File.Exists(path);

    public virtual FileInfo Info(string path) => new(path);

    public virtual string? ReadZone(string path) => MarkOfTheWeb.RawStream(path);

    public virtual void WriteZone(string path, string content) => File.WriteAllText(path + ":Zone.Identifier", content);

    public virtual void Flush(FileStream stream) => stream.Flush(flushToDisk: true);
}

/// <summary>The two Win32 calls the verified removal needs.</summary>
internal static partial class NativeDelete
{
    private const uint GenericRead = 0x80000000;
    private const uint Delete = 0x00010000;
    private const uint ShareRead = 0x1;
    private const uint OpenExisting = 3;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint SequentialScan = 0x08000000;
    private const int FileDispositionInfo = 4;
    private const uint ReparseAttribute = 0x400;

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeFileHandle CreateFile(string name, uint access, uint share, nint security, uint disposition, uint flags, nint template);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetFileInformationByHandle(SafeFileHandle file, int infoClass, ref int info, int size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation info);

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    /// <summary>Read and delete access, others may only read: no writer, rename or delete while it is held.</summary>
    public static SafeFileHandle OpenForVerifiedDelete(string path)
    {
        var handle = CreateFile(path, GenericRead | Delete, ShareRead, 0, OpenExisting, OpenReparsePoint | SequentialScan, 0);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            if (error == 5)
            {
                throw new UnauthorizedAccessException("the file could not be opened for a verified removal");
            }

            throw new IOException("the file could not be opened for a verified removal", unchecked((int)0x80070000) | error);
        }

        return handle;
    }

    public static bool IsReparsePoint(SafeFileHandle handle) =>
        !GetFileInformationByHandle(handle, out var info) || (info.FileAttributes & ReparseAttribute) != 0;

    public static void MarkForDeletion(SafeFileHandle handle)
    {
        var flag = 1;
        if (!SetFileInformationByHandle(handle, FileDispositionInfo, ref flag, sizeof(int)))
        {
            throw new IOException("the file could not be marked for removal", unchecked((int)0x80070000) | Marshal.GetLastWin32Error());
        }
    }
}

public sealed record QuarantineResult(bool Ok, string Reason, string? RestoredPath = null, long Size = 0, long ModifiedTicks = 0);

/// <summary>
/// Moves a flagged file into a private folder and back, without ever losing it. Rules, in order:
/// (1) nothing is touched unless the file is exactly the one that was judged (same SHA-256);
/// (2) the copy in quarantine is verified by hash before the original is let go (same volume: the
/// original is renamed, never copied and deleted; another volume: copy, verify, then remove);
/// (3) a record is written before anything irreversible, so a crash at any point can be resumed;
/// (4) every step is idempotent: doing it twice is a no-op that says so;
/// (5) restore never overwrites, never deletes the quarantine copy, and re-verifies the hash.
/// Nothing here deletes a user's file except the original after a verified copy on another volume.
/// </summary>
public sealed class QuarantineStore(string root, RealFileSystem? fileSystem = null)
{
    private const string Payload = "payload.quar";
    private const string Part = "payload.quar.part";
    private const string RecordFile = "record.json";

    private static readonly JsonSerializerOptions Json = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };
    private readonly RealFileSystem fs = fileSystem ?? new RealFileSystem();
    private readonly string root = Path.GetFullPath(root);

    public string Folder(string actionId) => Path.Combine(root, actionId);

    // ---- quarantine -------------------------------------------------------------------------

    public QuarantineResult Quarantine(string actionId, string path, string expectedSha256)
    {
        if (!Guid.TryParseExact(actionId, "D", out _))
        {
            return Fail("bad_id");
        }

        var dir = Folder(actionId);
        var record = Load(dir);
        if (record is { State: "quarantined" or "restored" } && fs.Exists(Path.Combine(dir, Payload)))
        {
            return new QuarantineResult(true, "already");
        }

        if (record is { State: "moving" or "copied" })
        {
            return Resume(dir, record);
        }

        try
        {
            if (Inspect(path) is { } problem)
            {
                return Fail(problem);
            }

            Directory.CreateDirectory(dir);
            return Begin(dir, actionId, path, expectedSha256.ToLowerInvariant());
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return Fail(Classify(e));
        }
    }

    private QuarantineResult Begin(string dir, string actionId, string path, string expected)
    {
        var part = Path.Combine(dir, Part);
        var sameVolume = fs.SameVolume(path, dir);
        FileInfo before;
        string hash;
        string? zone;
        using (var source = fs.OpenRead(path))
        {
            before = fs.Info(path);
            zone = fs.ReadZone(path);
            if (sameVolume)
            {
                hash = Hash(source);
            }
            else
            {
                (hash, _) = CopyAndHash(source, part);
            }

            if (hash != expected)
            {
                CleanTemp(part);
                return Fail("changed");
            }

            var record = new Record
            {
                ActionId = actionId,
                OriginalB64 = PathCodec.Encode(path),
                Sha256 = hash,
                Size = before.Length,
                ModifiedTicks = before.LastWriteTimeUtc.Ticks,
                Attributes = (int)before.Attributes,
                Zone = zone,
                State = "moving",
                At = DateTimeOffset.UtcNow,
            };
            Save(dir, record);
            if (sameVolume)
            {
                fs.Move(path, part); // the handle above allows rename; it blocks any writer
            }
        }

        return Finish(dir, Load(dir)!, path, sameVolume);
    }

    /// <summary>Picks up where an interrupted attempt stopped. Never starts over on top of a half state.</summary>
    private QuarantineResult Resume(string dir, Record record)
    {
        var path = PathCodec.Decode(record.OriginalB64) ?? string.Empty;
        var part = Path.Combine(dir, Part);
        var payload = Path.Combine(dir, Payload);
        try
        {
            if (fs.Exists(payload) && !fs.Exists(part))
            {
                return Finish(dir, record, path, sameVolume: true);
            }

            if (fs.Exists(part) && HashOf(part) != record.Sha256)
            {
                if (fs.Exists(path))
                {
                    CleanTemp(part); // the original is still there, so this was our own copy: a bad one
                    return Fail("changed");
                }

                fs.Move(part, path); // the original is gone: the part is the renamed user file, not ours to delete
                return Fail("payload_changed");
            }

            if (!fs.Exists(part) && !fs.Exists(payload))
            {
                if (!fs.Exists(path))
                {
                    return Fail("missing");
                }

                // nothing was moved yet: the original is where it was, so the record is stale; start again
                File.Delete(Path.Combine(dir, RecordFile));
                return Begin(dir, record.ActionId, path, record.Sha256);
            }

            return Finish(dir, record, path, sameVolume: !fs.Exists(path));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return Fail(Classify(e));
        }
    }

    private QuarantineResult Finish(string dir, Record record, string path, bool sameVolume)
    {
        var part = Path.Combine(dir, Part);
        var payload = Path.Combine(dir, Payload);
        if (fs.Exists(part))
        {
            if (HashOf(part) != record.Sha256)
            {
                if (sameVolume)
                {
                    // What was renamed is not what was judged (the name was swapped in a tiny window). It is
                    // somebody's file, not ours to delete: put it back, under a free name if the old one is taken.
                    fs.Move(part, fs.Exists(path) ? Unique(path) : path);
                    return Fail("changed");
                }

                CleanTemp(part); // a bad copy: the original was never touched
                return Fail("copy_failed");
            }

            fs.Move(part, payload);
        }

        if (fs.Exists(path))
        {
            // another volume: the verified copy is in place; now, and only now, the original may go
            var now = fs.Info(path);
            if (now.Length != record.Size || now.LastWriteTimeUtc.Ticks != record.ModifiedTicks)
            {
                return Fail("changed"); // it changed after it was judged: leave it alone, the copy stays
            }

            try
            {
                // the hash is checked through the very handle that is then marked for deletion; "copied" is
                // recorded just before, so a crash at any point can be resumed
                if (!RemoveVerifiedOriginal(path, record.Sha256, () =>
                    {
                        record.State = "copied";
                        Save(dir, record);
                    }))
                {
                    return Fail("changed"); // not the file that was judged (or a link): leave it, the copy stays
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                return Fail("remove_failed"); // both copies exist; a retry finishes the job
            }
        }

        record.State = "quarantined";
        Save(dir, record);
        return new QuarantineResult(true, "ok");
    }

    /// <summary>The single place a user's file is removed: its copy in quarantine has been verified byte for byte.</summary>
    private bool RemoveVerifiedOriginal(string path, string sha256, Action recordIntent) => fs.DeleteIfSame(path, sha256, recordIntent);

    // ---- restore ----------------------------------------------------------------------------

    public QuarantineResult Restore(string actionId)
    {
        if (!Guid.TryParseExact(actionId, "D", out _))
        {
            return Fail("bad_id");
        }

        var dir = Folder(actionId);
        var payload = Path.Combine(dir, Payload);
        var record = Load(dir);
        if (record is null)
        {
            return Fail("no_record");
        }

        if (record.State is not ("quarantined" or "restored") || !fs.Exists(payload))
        {
            return Fail("payload_missing");
        }

        if (record.State == "restored" && PathCodec.Decode(record.RestoredB64 ?? string.Empty) is { } there && fs.Exists(there))
        {
            return new QuarantineResult(true, "already", there);
        }

        try
        {
            if (HashOf(payload) != record.Sha256)
            {
                return Fail("payload_changed");
            }

            var original = PathCodec.Decode(record.OriginalB64) ?? string.Empty;
            if (!Path.IsPathRooted(original) || InsideStore(original) || original.StartsWith(@"\\", StringComparison.Ordinal))
            {
                return Fail("bad_path");
            }

            var folder = Path.GetDirectoryName(original);
            if (folder is null || !Directory.Exists(folder))
            {
                return Fail("folder_missing");
            }

            var target = fs.Exists(original) ? Unique(original) : original;
            var temp = target + ".lynceus-restore";
            if (fs.Exists(temp))
            {
                CleanTemp(temp);
            }

            using (var from = fs.OpenRead(payload))
            {
                CopyAndHash(from, temp);
            }

            if (HashOf(temp) != record.Sha256)
            {
                CleanTemp(temp);
                return Fail("io");
            }

            fs.Move(temp, target); // never overwrites
            // From here the file is back, so this is recorded first: a failure below must never make a
            // retry put a second copy next to it.
            record.State = "restored";
            record.RestoredB64 = PathCodec.Encode(target);
            Save(dir, record);

            var marked = true;
            if (!string.IsNullOrEmpty(record.Zone))
            {
                try
                {
                    fs.WriteZone(target, record.Zone);
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    marked = false; // the file is back but without its download mark: said, not hidden
                }
            }

            // last: writing the mark changes the file time, and the time is what keeps the agent from
            // judging the restored file as a new one
            try
            {
                File.SetLastWriteTimeUtc(target, new DateTime(record.ModifiedTicks, DateTimeKind.Utc));
                var keep = (FileAttributes)(record.Attributes & (int)(FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System | FileAttributes.Archive));
                File.SetAttributes(target, keep == 0 ? FileAttributes.Normal : keep);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // time and attributes are cosmetic next to having the file back
            }

            var reason = target == original ? "ok" : "renamed";
            return new QuarantineResult(true, marked ? reason : reason + "_unmarked", target, record.Size, record.ModifiedTicks);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return Fail(Classify(e));
        }
    }

    /// <summary>What a quarantined action holds, for the console and for tests. No path leaves the agent.</summary>
    public (string State, string Sha256, long Size)? Describe(string actionId) =>
        Guid.TryParseExact(actionId, "D", out _) && Load(Folder(actionId)) is { } r ? (r.State, r.Sha256, r.Size) : null;

    // ---- helpers ----------------------------------------------------------------------------

    private string? Inspect(string path)
    {
        if (string.IsNullOrEmpty(path) || !Path.IsPathRooted(path) || path.Contains(':', StringComparison.Ordinal) && path.LastIndexOf(':') > 1)
        {
            return "bad_path";
        }

        var full = Path.GetFullPath(path);
        if (InsideStore(full) || full.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return "bad_path"; // inside our own folder, or a network / device path (also spells \\localhost\C$\...)
        }

        var info = fs.Info(full);
        if (!info.Exists)
        {
            return Directory.Exists(full) ? "not_file" : "missing";
        }

        const FileAttributes recallOnOpen = (FileAttributes)0x40000;
        const FileAttributes recallOnDataAccess = (FileAttributes)0x400000;
        if ((info.Attributes & (FileAttributes.Offline | recallOnOpen | recallOnDataAccess)) != 0)
        {
            return "placeholder";
        }

        if (info.LinkTarget is not null)
        {
            return "link";
        }

        for (var parent = Path.GetDirectoryName(full); parent is not null; parent = Path.GetDirectoryName(parent))
        {
            if (new DirectoryInfo(parent).LinkTarget is not null)
            {
                return "link";
            }
        }

        return null;
    }

    /// <summary>True for the store folder itself or anything under it (a folder named like it, such as "quarantine-x", is not).</summary>
    private bool InsideStore(string fullPath)
    {
        var folder = root.EndsWith(Path.DirectorySeparatorChar) ? root : root + Path.DirectorySeparatorChar;
        return fullPath.StartsWith(folder, StringComparison.OrdinalIgnoreCase) || string.Equals(fullPath, root, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Sharing violation, access denied, or an antivirus block (ERROR_VIRUS_INFECTED / _DELETED).</summary>
    private static string Classify(Exception e)
    {
        if (e is UnauthorizedAccessException)
        {
            return "locked";
        }

        return e is IOException io ? (io.HResult & 0xFFFF) switch { 225 or 226 => "blocked", 32 or 33 => "locked", _ => "io" } : "io";
    }

    private static QuarantineResult Fail(string reason) => new(false, reason);

    private static string Hash(Stream stream)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[81920];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            sha.AppendData(buffer, 0, read);
        }

        return Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
    }

    private string HashOf(string path)
    {
        using var stream = fs.OpenRead(path);
        return Hash(stream);
    }

    private (string Hash, long Length) CopyAndHash(Stream source, string destination)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[81920];
        long total = 0;
        try
        {
            using var target = fs.CreateNew(destination);
            int read;
            while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
            {
                sha.AppendData(buffer, 0, read);
                target.Write(buffer, 0, read);
                total += read;
            }

            fs.Flush(target);
        }
        catch
        {
            CleanTemp(destination);
            throw;
        }

        return (Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant(), total);
    }

    /// <summary>Removes only a file this class made (a half-written copy), never a user's file.</summary>
    private void CleanTemp(string path)
    {
        try
        {
            if (fs.Exists(path) && (path.EndsWith(Part, StringComparison.Ordinal) || path.EndsWith(".lynceus-restore", StringComparison.Ordinal)))
            {
                fs.Delete(path);
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // left for the next attempt to clean
        }
    }

    private string Unique(string path)
    {
        var folder = Path.GetDirectoryName(path)!;
        var name = Path.GetFileNameWithoutExtension(path);
        var extension = Path.GetExtension(path);
        for (var i = 1; i < 1000; i++)
        {
            var candidate = Path.Combine(folder, $"{name} (restored {i}){extension}");
            if (!fs.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new IOException("no free name");
    }

    private static Record? Load(string dir)
    {
        try
        {
            return JsonSerializer.Deserialize<Record>(File.ReadAllText(Path.Combine(dir, RecordFile)), Json);
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static void Save(string dir, Record record)
    {
        Directory.CreateDirectory(dir);
        var temp = Path.Combine(dir, RecordFile + ".tmp");
        using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            stream.Write(JsonSerializer.SerializeToUtf8Bytes(record, Json));
            stream.Flush(flushToDisk: true); // on disk before it replaces the old record (a power cut keeps one good copy)
        }

        File.Move(temp, Path.Combine(dir, RecordFile), overwrite: true);
    }

    private sealed class Record
    {
        [JsonPropertyName("id")]
        public string ActionId { get; set; } = string.Empty;

        [JsonPropertyName("original")]
        public string OriginalB64 { get; set; } = string.Empty;

        [JsonPropertyName("sha256")]
        public string Sha256 { get; set; } = string.Empty;

        [JsonPropertyName("size")]
        public long Size { get; set; }

        [JsonPropertyName("mtime")]
        public long ModifiedTicks { get; set; }

        [JsonPropertyName("attrs")]
        public int Attributes { get; set; }

        [JsonPropertyName("zone")]
        public string? Zone { get; set; }

        [JsonPropertyName("state")]
        public string State { get; set; } = string.Empty;

        [JsonPropertyName("at")]
        public DateTimeOffset At { get; set; }

        [JsonPropertyName("restored")]
        public string? RestoredB64 { get; set; }
    }
}

/// <summary>A path as its exact UTF-16 code units in base64: NTFS allows names JSON cannot hold.</summary>
public static class PathCodec
{
    public static string Encode(string path) => Convert.ToBase64String(MemoryMarshal.AsBytes(path.AsSpan()));

    public static string? Decode(string encoded)
    {
        try
        {
            var bytes = Convert.FromBase64String(encoded);
            return bytes.Length % 2 == 0 ? new string(MemoryMarshal.Cast<byte, char>(bytes)) : null;
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
