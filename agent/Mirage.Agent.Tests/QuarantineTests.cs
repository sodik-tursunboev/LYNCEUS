using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Mirage.Agent.Tests;

public sealed class SimulatedCrashException : Exception;

/// <summary>A file system that can be told to fail, crash, or report another volume, and that logs what it did.</summary>
public sealed class FaultFs : RealFileSystem
{
    public bool CrossVolume { get; set; }

    public List<string> Ops { get; } = [];

    public Action<string, string>? BeforeMove { get; set; }

    public Action<string, string>? AfterMove { get; set; }

    public Action<string>? BeforeDelete { get; set; }

    /// <summary>Runs while the verified removal holds the file: whatever it tries on the file must fail.</summary>
    public Action<string>? WhileDeleting { get; set; }

    public Action<string>? OnWriteZone { get; set; }

    public Action<string>? OnCreate { get; set; }

    public Action<FileStream>? OnFlush { get; set; }

    public Action? WhileHeld { get; set; }

    public override bool SameVolume(string a, string b) => !CrossVolume && base.SameVolume(a, b);

    public override FileStream OpenRead(string path)
    {
        var stream = base.OpenRead(path);
        WhileHeld?.Invoke();
        return stream;
    }

    public override FileStream CreateNew(string path)
    {
        OnCreate?.Invoke(path);
        Ops.Add("create");
        return base.CreateNew(path);
    }

    public override void Move(string source, string destination)
    {
        BeforeMove?.Invoke(source, destination);
        Ops.Add("move");
        base.Move(source, destination);
        AfterMove?.Invoke(source, destination);
    }

    public override void Delete(string path)
    {
        BeforeDelete?.Invoke(path);
        Ops.Add("delete");
        base.Delete(path);
    }

    public override bool DeleteIfSame(string path, string sha256, Action beforeDelete)
    {
        BeforeDelete?.Invoke(path);
        Ops.Add("delete");
        return base.DeleteIfSame(path, sha256, () =>
        {
            WhileDeleting?.Invoke(path);
            beforeDelete();
        });
    }

    public override void WriteZone(string path, string content)
    {
        OnWriteZone?.Invoke(path);
        base.WriteZone(path, content);
    }

    public override void Flush(FileStream stream)
    {
        OnFlush?.Invoke(stream);
        base.Flush(stream);
    }
}

public class QuarantineTests : IDisposable
{
    private readonly TestDir dir = new();
    private readonly string quarantine;
    private readonly string downloads;

    public QuarantineTests()
    {
        quarantine = dir.Sub("quarantine");
        downloads = dir.Sub("downloads");
    }

    private static readonly byte[] Content = Encoding.ASCII.GetBytes("MZ pretend this is dangerous " + new string('x', 5000));
    private static string Sha(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
    private static string NewId() => Guid.NewGuid().ToString("D");

    private (string Path, string Sha) Drop(string name = "invoice.pdf.exe", byte[]? data = null)
    {
        var path = Path.Combine(downloads, name);
        File.WriteAllBytes(path, data ?? Content);
        return (path, Sha(data ?? Content));
    }

    private QuarantineStore Store(FaultFs? fs = null) => new(quarantine, fs);

    public void Dispose()
    {
        dir.Dispose();
        GC.SuppressFinalize(this);
    }

    // ---- the ordinary path ---------------------------------------------------------------------

    [Fact]
    public void A_file_is_moved_to_a_neutral_name_in_a_folder_of_its_own_and_the_original_is_gone()
    {
        var (path, sha) = Drop();
        var id = NewId();
        var result = Store().Quarantine(id, path, sha);
        Assert.Equal((true, "ok"), (result.Ok, result.Reason));
        Assert.False(File.Exists(path));
        var folder = Path.Combine(quarantine, id);
        Assert.Equal("payload.quar,record.json", string.Join(",", Directory.GetFileSystemEntries(folder).Select(e => Path.GetFileName(e)).Order()));
        Assert.Equal(Content, File.ReadAllBytes(Path.Combine(folder, "payload.quar")));
        Assert.Equal(("quarantined", sha), (Store().Describe(id)!.Value.State, Store().Describe(id)!.Value.Sha256));
        Assert.DoesNotContain("invoice", File.ReadAllText(Path.Combine(folder, "record.json")), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Doing_it_twice_is_a_no_op_that_says_so_and_does_not_touch_a_new_file_at_the_old_path()
    {
        var (path, sha) = Drop();
        var id = NewId();
        var store = Store();
        store.Quarantine(id, path, sha);
        var again = store.Quarantine(id, path, sha);
        Assert.Equal((true, "already"), (again.Ok, again.Reason));
        File.WriteAllText(path, "a different file now at the same place");
        Assert.Equal("already", store.Quarantine(id, path, sha).Reason);
        Assert.Equal("a different file now at the same place", File.ReadAllText(path));
    }

    [Fact]
    public void Restore_brings_back_the_same_bytes_time_attributes_and_mark_of_the_web_and_keeps_the_quarantine_copy()
    {
        var (path, sha) = Drop();
        File.WriteAllText(path + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://origin.test/a\r\n");
        File.SetAttributes(path, FileAttributes.ReadOnly);
        var time = File.GetLastWriteTimeUtc(path);
        var id = NewId();
        var store = Store();
        Assert.True(store.Quarantine(id, path, sha).Ok);
        Assert.False(File.Exists(path));

        var result = store.Restore(id);
        Assert.Equal((true, "ok", path), (result.Ok, result.Reason, result.RestoredPath));
        Assert.Equal(Content, File.ReadAllBytes(path));
        Assert.Equal(time, File.GetLastWriteTimeUtc(path));
        Assert.True(File.GetAttributes(path).HasFlag(FileAttributes.ReadOnly));
        Assert.Contains("ZoneId=3", MarkOfTheWeb.RawStream(path), StringComparison.Ordinal);
        Assert.True(File.Exists(Path.Combine(quarantine, id, "payload.quar")));
        Assert.Equal("restored", store.Describe(id)!.Value.State);
        File.SetAttributes(path, FileAttributes.Normal);
    }

    [Fact]
    public void Restoring_twice_is_a_no_op_and_restoring_after_the_user_deleted_it_works_again()
    {
        var (path, sha) = Drop();
        var id = NewId();
        var store = Store();
        store.Quarantine(id, path, sha);
        store.Restore(id);
        Assert.Equal("already", store.Restore(id).Reason);
        File.Delete(path);
        Assert.Equal("ok", store.Restore(id).Reason);
        Assert.Equal(Content, File.ReadAllBytes(path));
    }

    [Fact]
    public void Restore_never_overwrites_a_file_that_is_now_at_the_old_name()
    {
        var (path, sha) = Drop();
        var id = NewId();
        var store = Store();
        store.Quarantine(id, path, sha);
        File.WriteAllText(path, "someone else's file");
        var result = store.Restore(id);
        Assert.Equal((true, "renamed"), (result.Ok, result.Reason));
        Assert.Equal("someone else's file", File.ReadAllText(path));
        Assert.EndsWith("invoice.pdf (restored 1).exe", result.RestoredPath, StringComparison.Ordinal);
        Assert.Equal(Content, File.ReadAllBytes(result.RestoredPath!));
    }

    [Fact]
    public void Restore_fails_safely_when_the_folder_is_gone_the_payload_was_changed_or_there_is_no_record()
    {
        var sub = Path.Combine(downloads, "gone");
        Directory.CreateDirectory(sub);
        var (path, sha) = Drop("gone\\a.bin");
        var id = NewId();
        var store = Store();
        store.Quarantine(id, path, sha);
        Directory.Delete(sub);
        Assert.Equal((false, "folder_missing"), (store.Restore(id).Ok, store.Restore(id).Reason));
        Assert.True(File.Exists(Path.Combine(quarantine, id, "payload.quar")));

        var (path2, sha2) = Drop("b.bin", [1, 2, 3, 4]);
        var id2 = NewId();
        store.Quarantine(id2, path2, sha2);
        File.AppendAllText(Path.Combine(quarantine, id2, "payload.quar"), "tampered");
        Assert.Equal("payload_changed", store.Restore(id2).Reason);
        Assert.False(File.Exists(path2));

        Assert.Equal("no_record", store.Restore(NewId()).Reason);
        Assert.Equal("bad_id", store.Restore("../x").Reason);
    }

    // ---- fail-safe: the original is never touched ---------------------------------------------

    private void AssertUntouched(string path, byte[] expected)
    {
        Assert.True(File.Exists(path));
        Assert.Equal(expected, File.ReadAllBytes(path));
        Assert.Empty(Directory.GetFiles(quarantine, "payload*", SearchOption.AllDirectories));
    }

    [Fact]
    public void A_file_that_is_not_the_one_that_was_judged_is_left_alone()
    {
        var (path, _) = Drop();
        var result = Store().Quarantine(NewId(), path, new string('0', 64));
        Assert.Equal((false, "changed"), (result.Ok, result.Reason));
        AssertUntouched(path, Content);
    }

    [Fact]
    public void A_missing_file_a_folder_a_relative_path_and_a_path_inside_quarantine_are_refused()
    {
        var store = Store();
        Assert.Equal("missing", store.Quarantine(NewId(), Path.Combine(downloads, "nope.bin"), Sha(Content)).Reason);
        Assert.Equal("not_file", store.Quarantine(NewId(), downloads, Sha(Content)).Reason);
        Assert.Equal("bad_path", store.Quarantine(NewId(), "relative\\a.bin", Sha(Content)).Reason);
        Assert.Equal("bad_path", store.Quarantine(NewId(), "", Sha(Content)).Reason);
        var inside = Path.Combine(quarantine, "x.bin");
        File.WriteAllBytes(inside, Content);
        Assert.Equal("bad_path", store.Quarantine(NewId(), inside, Sha(Content)).Reason);
        Assert.Equal("bad_path", store.Quarantine(NewId(), Path.Combine(downloads, "a.bin:Zone.Identifier"), Sha(Content)).Reason);
        foreach (var bad in new[] { "", "../x", "not-a-guid", NewId() + "/.." })
        {
            Assert.Equal("bad_id", store.Quarantine(bad, Path.Combine(downloads, "a"), Sha(Content)).Reason);
        }
    }

    [Fact]
    public void A_file_held_open_for_writing_is_reported_locked_and_untouched()
    {
        var (path, sha) = Drop();
        using var holder = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        var result = Store().Quarantine(NewId(), path, sha);
        Assert.Equal((false, "locked"), (result.Ok, result.Reason));
        holder.Dispose();
        AssertUntouched(path, Content);
    }

    [Fact]
    public void A_junction_a_cloud_placeholder_and_a_file_behind_a_link_are_not_followed()
    {
        var outside = dir.Sub("outside");
        File.WriteAllBytes(Path.Combine(outside, "real.bin"), Content);
        var link = Path.Combine(downloads, "link");
        var made = Process.Start(new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{outside}\"") { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true });
        made!.WaitForExit();
        try
        {
            Assert.Equal("link", Store().Quarantine(NewId(), Path.Combine(link, "real.bin"), Sha(Content)).Reason);
            Assert.True(File.Exists(Path.Combine(outside, "real.bin")));
        }
        finally
        {
            Directory.Delete(link);
        }

        var (path, sha) = Drop("placeholder.bin");
        File.SetAttributes(path, FileAttributes.Offline);
        Assert.Equal("placeholder", Store().Quarantine(NewId(), path, sha).Reason);
        File.SetAttributes(path, FileAttributes.Normal);
        AssertUntouched(path, Content);
    }

    [Fact]
    public void A_file_that_is_itself_a_symbolic_link_is_not_followed_if_this_account_may_create_one()
    {
        var target = Path.Combine(dir.Sub("elsewhere"), "real.bin");
        File.WriteAllBytes(target, Content);
        var link = Path.Combine(downloads, "symlinked.bin");
        try
        {
            File.CreateSymbolicLink(link, target);
        }
        catch (Exception e) when (e is UnauthorizedAccessException or IOException)
        {
            return; // creating symbolic links needs a privilege this account may not have; the junction test covers a linked folder
        }

        Assert.Equal("link", Store().Quarantine(NewId(), link, Sha(Content)).Reason);
        Assert.True(File.Exists(target));
    }

    [Fact]
    public void While_the_file_is_being_hashed_nobody_can_write_to_it_so_what_is_hashed_is_what_is_moved()
    {
        var (path, sha) = Drop();
        var fs = new FaultFs();
        Exception? writer = null;
        fs.WhileHeld = () =>
        {
            try
            {
                using var w = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
                w.WriteByte(0);
            }
            catch (IOException e)
            {
                writer = e;
            }
        };
        Assert.True(Store(fs).Quarantine(NewId(), path, sha).Ok);
        Assert.NotNull(writer);
    }

    // ---- another volume: copy, verify, and only then remove ------------------------------------

    [Fact]
    public void On_another_volume_the_original_is_removed_only_after_the_copy_is_verified_in_place()
    {
        var (path, sha) = Drop();
        var id = NewId();
        var fs = new FaultFs { CrossVolume = true };
        string? payloadAtDelete = null;
        fs.BeforeDelete = p =>
        {
            Assert.Equal(path, p);
            payloadAtDelete = Sha(File.ReadAllBytes(Path.Combine(quarantine, id, "payload.quar")));
        };
        Assert.True(Store(fs).Quarantine(id, path, sha).Ok);
        Assert.Equal(sha, payloadAtDelete);
        Assert.False(File.Exists(path));
        Assert.Equal(1, fs.Ops.Count(o => o == "delete"));
    }

    [Fact]
    public void A_copy_that_fails_or_is_corrupt_leaves_the_original_and_no_half_file()
    {
        var (path, sha) = Drop();
        var disk = new FaultFs { CrossVolume = true, OnCreate = _ => throw new IOException("There is not enough space on the disk.") };
        Assert.Equal((false, "io"), (Store(disk).Quarantine(NewId(), path, sha).Ok, Store(disk).Quarantine(NewId(), path, sha).Reason));
        AssertUntouched(path, Content);

        var corrupt = new FaultFs
        {
            CrossVolume = true,
            OnFlush = s =>
            {
                s.Position = 3;
                s.WriteByte(0xFF);
            },
        };
        var id = NewId();
        Assert.Equal("copy_failed", Store(corrupt).Quarantine(id, path, sha).Reason);
        AssertUntouched(path, Content);
        Assert.True(Store().Quarantine(id, path, sha).Ok); // a clean retry works
    }

    [Fact]
    public void If_removing_the_original_fails_both_copies_exist_and_a_retry_finishes_the_job()
    {
        var (path, sha) = Drop();
        var id = NewId();
        var fs = new FaultFs { CrossVolume = true, BeforeDelete = _ => throw new IOException("in use") };
        var first = Store(fs).Quarantine(id, path, sha);
        Assert.Equal((false, "remove_failed"), (first.Ok, first.Reason));
        Assert.True(File.Exists(path) && File.Exists(Path.Combine(quarantine, id, "payload.quar")));
        Assert.True(Store().Quarantine(id, path, sha).Ok);
        Assert.False(File.Exists(path));
        Assert.Equal("quarantined", Store().Describe(id)!.Value.State);
    }

    [Fact]
    public void A_file_that_changed_after_it_was_copied_is_kept_and_the_failure_is_stated()
    {
        var (path, sha) = Drop();
        var fs = new FaultFs { CrossVolume = true };
        fs.AfterMove = (_, _) => File.AppendAllText(path, "changed after the copy");
        var result = Store(fs).Quarantine(NewId(), path, sha);
        Assert.Equal((false, "changed"), (result.Ok, result.Reason));
        Assert.EndsWith("changed after the copy", File.ReadAllText(path), StringComparison.Ordinal);
    }

    // ---- a crash at any step can be resumed without loss or duplication ------------------------

    [Theory]
    [InlineData(false, true)]
    [InlineData(false, false)]
    [InlineData(true, true)]
    [InlineData(true, false)]
    public void A_crash_around_the_move_is_resumed_by_the_next_attempt(bool crossVolume, bool crashBefore)
    {
        var (path, sha) = Drop();
        var id = NewId();
        var fs = new FaultFs { CrossVolume = crossVolume };
        if (crashBefore)
        {
            fs.BeforeMove = (_, _) => throw new SimulatedCrashException();
        }
        else
        {
            fs.AfterMove = (_, _) => throw new SimulatedCrashException();
        }

        Assert.Throws<SimulatedCrashException>(() => Store(fs).Quarantine(id, path, sha));
        var result = Store().Quarantine(id, path, sha);
        Assert.True(result.Ok, result.Reason);
        Assert.False(File.Exists(path));
        Assert.Equal(Content, File.ReadAllBytes(Path.Combine(quarantine, id, "payload.quar")));
        Assert.Equal("payload.quar,record.json", string.Join(",", Directory.GetFileSystemEntries(Path.Combine(quarantine, id)).Select(e => Path.GetFileName(e)).Order()));
        Assert.True(Store().Restore(id).Ok);
        Assert.Equal(Content, File.ReadAllBytes(path));
    }

    [Fact]
    public void A_crash_while_removing_the_original_loses_nothing()
    {
        var (path, sha) = Drop();
        var id = NewId();
        var fs = new FaultFs { CrossVolume = true, BeforeDelete = _ => throw new SimulatedCrashException() };
        Assert.Throws<SimulatedCrashException>(() => Store(fs).Quarantine(id, path, sha));
        Assert.True(File.Exists(path) && File.Exists(Path.Combine(quarantine, id, "payload.quar")));
        Assert.True(Store().Quarantine(id, path, sha).Ok);
        Assert.False(File.Exists(path));
    }

    // ---- reviewer findings: races, retries, durability -------------------------------------------

    [Fact]
    public void The_original_cannot_be_swapped_while_it_is_being_verified_and_removed()
    {
        var (path, sha) = Drop();
        var intruder = Path.Combine(downloads, "intruder.bin");
        File.WriteAllText(intruder, "somebody else's newer file");
        var attempts = new List<string>();
        var fs = new FaultFs { CrossVolume = true };
        fs.WhileDeleting = p =>
        {
            foreach (var (name, act) in new (string, Action)[]
            {
                ("replace", () => File.Move(intruder, p, overwrite: true)),
                ("delete", () => File.Delete(p)),
                ("rename away", () => File.Move(p, p + ".moved")),
                ("write", () => File.AppendAllText(p, "x")),
            })
            {
                try
                {
                    act();
                    attempts.Add(name + ": SUCCEEDED");
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    attempts.Add(name + ": refused");
                }
            }
        };
        Assert.True(Store(fs).Quarantine(NewId(), path, sha).Ok);
        Assert.Equal(["replace: refused", "delete: refused", "rename away: refused", "write: refused"], attempts);
        Assert.False(File.Exists(path)); // the verified original went
        Assert.Equal("somebody else's newer file", File.ReadAllText(intruder)); // the other file is untouched
    }

    [Fact]
    public void A_same_size_same_time_substitute_is_caught_by_the_hash_and_nothing_is_deleted()
    {
        var (path, sha) = Drop();
        var time = File.GetLastWriteTimeUtc(path);
        var fs = new FaultFs { CrossVolume = true };
        fs.AfterMove = (_, _) =>
        {
            File.WriteAllBytes(path, new string('Q', Content.Length).Select(c => (byte)c).ToArray());
            File.SetLastWriteTimeUtc(path, time); // same length, same time: only the content differs
        };
        var result = Store(fs).Quarantine(NewId(), path, sha);
        Assert.Equal((false, "changed"), (result.Ok, result.Reason));
        Assert.True(File.Exists(path) && File.ReadAllText(path).StartsWith("QQQ", StringComparison.Ordinal));
    }

    [Fact]
    public void A_file_swapped_in_just_before_the_rename_is_put_back_not_deleted_even_if_its_name_is_taken_again()
    {
        var (path, sha) = Drop();
        var fs = new FaultFs();
        var swapped = false;
        fs.BeforeMove = (_, _) =>
        {
            if (swapped)
            {
                return; // only the first move is the one being raced; the put-back must not be
            }

            swapped = true;
            File.Move(path, path + ".orig");
            File.WriteAllText(path, "Y: the user's other file");
        };
        fs.AfterMove = (_, _) =>
        {
            if (!File.Exists(path))
            {
                File.WriteAllText(path, "Z: created at the old name afterwards");
            }
        };
        var result = Store(fs).Quarantine(NewId(), path, sha);
        Assert.Equal((false, "changed"), (result.Ok, result.Reason));
        var everything = Directory.GetFiles(downloads).Select(File.ReadAllText).ToList();
        Assert.Contains("Y: the user's other file", everything);
        Assert.Contains("Z: created at the old name afterwards", everything);
        Assert.Equal(3, everything.Count); // the original (renamed away), Y and Z: nothing was deleted
    }

    [Fact]
    public void After_a_crash_a_swapped_part_is_put_back_at_the_original_name_not_deleted()
    {
        var (path, sha) = Drop();
        var id = NewId();
        var fs = new FaultFs();
        fs.BeforeMove = (_, _) =>
        {
            File.Move(path, path + ".orig");
            File.WriteAllText(path, "Y: the user's other file");
        };
        fs.AfterMove = (_, _) => throw new SimulatedCrashException();
        Assert.Throws<SimulatedCrashException>(() => Store(fs).Quarantine(id, path, sha));
        var result = Store().Quarantine(id, path, sha);
        Assert.False(result.Ok);
        Assert.Equal("Y: the user's other file", File.ReadAllText(path));
    }

    [Fact]
    public void A_restore_whose_finishing_touches_fail_leaves_one_file_and_says_so_and_a_retry_adds_no_copy()
    {
        var (path, sha) = Drop();
        File.WriteAllText(path + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\n");
        var id = NewId();
        Store().Quarantine(id, path, sha);
        var fs = new FaultFs { OnWriteZone = _ => throw new IOException("the mark could not be written") };
        var first = Store(fs).Restore(id);
        Assert.Equal((true, "ok_unmarked"), (first.Ok, first.Reason));
        var again = Store().Restore(id);
        Assert.Equal((true, "already"), (again.Ok, again.Reason));
        Assert.Equal([Path.GetFileName(path)], Directory.GetFiles(downloads).Select(Path.GetFileName)); // no "(restored n)" copies
        Assert.Equal(Content, File.ReadAllBytes(path));
    }

    [Fact]
    public void A_quarantine_folder_that_cannot_be_made_is_a_stated_failure_not_an_exception()
    {
        var (path, sha) = Drop();
        var id = NewId();
        File.WriteAllText(Path.Combine(quarantine, id), "in the way");
        var result = Store().Quarantine(id, path, sha);
        Assert.Equal((false, "io"), (result.Ok, result.Reason));
        AssertUntouched(path, Content);
    }

    [Fact]
    public void Inside_the_store_means_inside_the_folder_a_sibling_folder_is_fine_and_a_network_spelling_is_refused()
    {
        var sibling = dir.Sub("quarantine-sibling");
        var inSibling = Path.Combine(sibling, "a.exe");
        File.WriteAllBytes(inSibling, Content);
        Assert.True(Store().Quarantine(NewId(), inSibling, Sha(Content)).Ok); // not mistaken for the store

        var id = NewId();
        var (path, sha) = Drop();
        Store().Quarantine(id, path, sha);
        var payload = Path.Combine(quarantine, id, "payload.quar");
        Assert.Equal("bad_path", Store().Quarantine(NewId(), payload, sha).Reason); // the store itself
        var drive = Path.GetPathRoot(payload)![..1];
        var unc = @"\\localhost\" + drive + "$" + payload[2..]; // the same file spelled as a network path
        Assert.Equal("bad_path", Store().Quarantine(NewId(), unc, sha).Reason);
    }

    // ---- nothing deletes a user's file except the verified-original removal --------------------

    [Fact]
    public void The_agent_has_exactly_the_delete_calls_that_were_reviewed()
    {
        var root = AppContext.BaseDirectory;
        while (root is not null && !File.Exists(Path.Combine(root, "Mirage.slnx")))
        {
            root = Path.GetDirectoryName(root);
        }

        Assert.NotNull(root);
        var sources = Directory.GetFiles(root!, "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains(@"\obj\", StringComparison.Ordinal) && !f.Contains(@"\bin\", StringComparison.Ordinal) && !f.Contains("Tests", StringComparison.Ordinal));
        var found = sources
            .Select(f => (File: Path.GetFileName(f), Count: Regex.Count(File.ReadAllText(f), @"\b(File|Directory|fs)\.Delete\(")))
            .Where(x => x.Count > 0)
            .OrderBy(x => x.File)
            .ToList();
        // Installer: our own host manifest on uninstall. QuarantineStore: the file system wrapper (1), the stale
        // record of an attempt that moved nothing (1) and a half-written copy this class made (1). The verified
        // original after a copy to another volume goes through DeleteIfSame (checked below). Nothing else may delete.
        Assert.Equal([("Installer.cs", 1), ("QuarantineStore.cs", 3)], found);
        // ... and the one place a user's file goes: the verified removal through a pinned handle
        var verified = sources
            .Select(f => (File: Path.GetFileName(f), Count: Regex.Count(File.ReadAllText(f), @"\b(DeleteIfSame|MarkForDeletion)\(")))
            .Where(x => x.Count > 0)
            .OrderBy(x => x.File)
            .ToList();
        Assert.Equal([("QuarantineStore.cs", 4)], verified);
    }
}
