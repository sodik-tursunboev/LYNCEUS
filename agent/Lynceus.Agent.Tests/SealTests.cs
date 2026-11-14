using System.Security.Cryptography;
using System.Text;

namespace Lynceus.Agent.Tests;

/// <summary>
/// H1 A7: a quarantined copy is sealed (AES-256 counter mode, the key under DPAPI). Nothing of the file stays
/// readable in the folder, restore gives back the exact bytes, tampering is caught by the judged hash, an
/// interrupted seal is finished, and older plain copies are sealed when the agent starts.
/// </summary>
public sealed class SealTests : IDisposable
{
    private static readonly byte[] Content = Encoding.ASCII.GetBytes("MZ pretend this is dangerous EICAR-like " + new string('x', 200_003));
    private readonly TestDir dir = new();
    private readonly string quarantine;
    private readonly string downloads;

    public SealTests()
    {
        quarantine = dir.Sub("quarantine");
        downloads = dir.Sub("downloads");
    }

    public void Dispose()
    {
        dir.Dispose();
        GC.SuppressFinalize(this);
    }

    private static string Sha(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private (string Id, string Path) Quarantined(QuarantineStore store)
    {
        var path = Path.Combine(downloads, "invoice.pdf.exe");
        File.WriteAllBytes(path, Content);
        var id = Guid.NewGuid().ToString("D");
        Assert.True(store.Quarantine(id, path, Sha(Content)).Ok);
        return (id, path);
    }

    private static bool Contains(byte[] haystack, byte[] needle) => haystack.AsSpan().IndexOf(needle) >= 0;

    [Fact]
    public void A_sealed_copy_holds_nothing_readable_and_restores_to_the_exact_bytes()
    {
        var store = new QuarantineStore(quarantine);
        var (id, path) = Quarantined(store);
        var seal = store.Seal(id);
        Assert.Equal((true, "ok"), (seal.Ok, seal.Reason));
        Assert.Equal("already", store.Seal(id).Reason);
        var folder = Path.Combine(quarantine, id);
        Assert.Equal("payload.sealed,record.json", string.Join(",", Directory.GetFileSystemEntries(folder).Select(e => Path.GetFileName(e)).Order()));
        var sealedBytes = File.ReadAllBytes(Path.Combine(folder, "payload.sealed"));
        Assert.Equal(Content.Length, sealedBytes.Length);
        Assert.False(Contains(sealedBytes, "MZ pretend"u8.ToArray()));
        Assert.False(Contains(sealedBytes, "xxxxxxxxxxxxxxxx"u8.ToArray())); // no repeating plain block shows through
        Assert.True(store.IsSealed(id));

        var restored = store.Restore(id);
        Assert.True(restored.Ok, restored.Reason);
        Assert.Equal(Content, File.ReadAllBytes(path));
    }

    [Fact]
    public void Two_files_with_the_same_content_get_different_keys_and_different_bytes()
    {
        var store = new QuarantineStore(quarantine);
        var (a, _) = Quarantined(store);
        var (b, _) = Quarantined(store);
        store.Seal(a);
        store.Seal(b);
        Assert.NotEqual(File.ReadAllBytes(Path.Combine(quarantine, a, "payload.sealed")), File.ReadAllBytes(Path.Combine(quarantine, b, "payload.sealed")));
    }

    [Fact]
    public void A_tampered_sealed_copy_is_refused_and_nothing_is_written_next_to_the_original_place()
    {
        var store = new QuarantineStore(quarantine);
        var (id, path) = Quarantined(store);
        store.Seal(id);
        var sealedPath = Path.Combine(quarantine, id, "payload.sealed");
        var bytes = File.ReadAllBytes(sealedPath);
        bytes[1000] ^= 0x55;
        File.WriteAllBytes(sealedPath, bytes);
        Assert.Equal("payload_changed", store.Restore(id).Reason);
        Assert.False(File.Exists(path));
        Assert.Empty(Directory.GetFiles(downloads));
    }

    [Fact]
    public void A_seal_interrupted_after_the_record_is_finished_on_the_next_try()
    {
        var crashOnce = true;
        var fs = new FaultFs
        {
            BeforeMove = (from, _) =>
            {
                if (crashOnce && from.EndsWith("payload.sealed.part", StringComparison.Ordinal))
                {
                    crashOnce = false;
                    throw new SimulatedCrashException();
                }
            },
        };
        var store = new QuarantineStore(quarantine, fs);
        var (id, path) = Quarantined(store);
        Assert.Throws<SimulatedCrashException>(() => store.Seal(id));
        Assert.True(File.Exists(Path.Combine(quarantine, id, "payload.quar"))); // the plain copy is still there

        Assert.Equal(1, new QuarantineStore(quarantine).SealAll()); // what the agent does at its next start
        var after = new QuarantineStore(quarantine);
        Assert.True(after.IsSealed(id));
        Assert.False(File.Exists(Path.Combine(quarantine, id, "payload.quar")));
        Assert.True(after.Restore(id).Ok);
        Assert.Equal(Content, File.ReadAllBytes(path));
    }

    [Fact]
    public void Older_plain_copies_are_sealed_at_start_and_restored_ones_too()
    {
        var store = new QuarantineStore(quarantine);
        var (first, _) = Quarantined(store);
        var (second, path2) = Quarantined(store);
        Assert.True(store.Restore(second).Ok); // restored, its quarantine copy stays
        File.Delete(path2);
        Assert.Equal(2, store.SealAll());
        Assert.True(store.IsSealed(first) && store.IsSealed(second));
        Assert.Equal(0, store.SealAll()); // nothing left to do
    }

    [Fact]
    public void A_quarantine_that_is_already_sealed_is_still_already_done()
    {
        var store = new QuarantineStore(quarantine);
        var (id, path) = Quarantined(store);
        store.Seal(id);
        File.WriteAllBytes(path, Content); // the same name is used again for a new download
        Assert.Equal("already", store.Quarantine(id, path, Sha(Content)).Reason);
        Assert.True(File.Exists(path)); // not touched
    }
}
