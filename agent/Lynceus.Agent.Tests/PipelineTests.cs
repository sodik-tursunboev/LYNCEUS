using System.Diagnostics;
using System.Net;
using System.Text;

namespace Lynceus.Agent.Tests;

public class PipelineTests
{
    private static readonly byte[] Pdf = Encoding.ASCII.GetBytes("%PDF-1.7\nhello");

    private static int Analyzed(Rig rig) => rig.Fake.To("/v1/files/analyze").Count;

    [Fact]
    public async Task A_dropped_file_reaches_the_core_with_its_own_hash_and_a_verdict_comes_back()
    {
        using var dir = new TestDir();
        using var rig = new Rig(dir.Path);
        rig.Start();
        rig.Write("report.pdf", Pdf);
        await Wait.Until(() => rig.Judged == 1, "one verdict");

        var seen = Assert.Single(rig.Fake.To("/v1/files/analyze"));
        Assert.Equal(("report.pdf", Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Pdf)).ToLowerInvariant(), "Bearer test-token"), (seen.Name, seen.Sha, seen.Auth));
        Assert.Equal(Pdf, seen.Body);
        var outcome = rig.Outcomes.Single();
        Assert.Equal(("SUSPICIOUS", "pdf"), (outcome.Verdict.State, outcome.Magic));
        Assert.Empty(rig.Spool.Snapshot());
    }

    [Fact]
    public async Task A_download_in_progress_is_ignored_until_it_gets_its_real_name()
    {
        using var dir = new TestDir();
        using var rig = new Rig(dir.Path);
        rig.Start();
        var partial = rig.Write("setup.zip.crdownload", Encoding.ASCII.GetBytes("PK\x03\x04partial"));
        await Task.Delay(400);
        Assert.Empty(rig.Fake.Requests);
        File.Move(partial, Path.Combine(rig.Watched, "setup.zip"));
        await Wait.Until(() => rig.Judged == 1, "the renamed file");
        Assert.Equal("setup.zip", Assert.Single(rig.Fake.To("/v1/files/analyze")).Name);
    }

    [Fact]
    public async Task A_file_that_is_still_growing_is_read_once_when_it_is_finished()
    {
        using var dir = new TestDir();
        using var rig = new Rig(dir.Path, tweak: c => c with { StableMillis = 200 });
        rig.Start();
        var path = Path.Combine(rig.Watched, "grow.bin");
        var expected = new List<byte>();
        await using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.ReadWrite))
        {
            for (var i = 0; i < 12; i++)
            {
                var chunk = Encoding.ASCII.GetBytes($"chunk {i}\n");
                expected.AddRange(chunk);
                await stream.WriteAsync(chunk);
                await stream.FlushAsync();
                await Task.Delay(50);
            }
        }

        await Wait.Until(() => rig.Judged == 1, "the finished file");
        await Task.Delay(300);
        var seen = Assert.Single(rig.Fake.To("/v1/files/analyze"));
        Assert.Equal(expected.ToArray(), seen.Body);
    }

    [Fact]
    public async Task A_file_held_open_for_writing_waits_until_it_is_released()
    {
        using var dir = new TestDir();
        using var rig = new Rig(dir.Path);
        rig.Start();
        var path = Path.Combine(rig.Watched, "locked.bin");
        var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
        await stream.WriteAsync(Pdf);
        await stream.FlushAsync();
        await Task.Delay(500);
        Assert.Empty(rig.Fake.Requests);
        await stream.DisposeAsync();
        await Wait.Until(() => rig.Judged == 1, "the released file");
        Assert.Equal(Pdf, Assert.Single(rig.Fake.To("/v1/files/analyze")).Body);
    }

    [Fact]
    public async Task A_file_over_the_limit_is_described_not_sent()
    {
        using var dir = new TestDir();
        using var rig = new Rig(dir.Path, tweak: c => c with { MaxInspectBytes = 100 });
        rig.Start();
        var big = new byte[5000];
        big[0] = 0x50;
        big[1] = 0x4b;
        big[2] = 3;
        big[3] = 4;
        rig.Write("big.zip", big);
        await Wait.Until(() => rig.Judged == 1, "a verdict");
        Assert.Empty(rig.Fake.To("/v1/files/analyze"));
        var seen = Assert.Single(rig.Fake.To("/v1/files/check"));
        var text = Encoding.UTF8.GetString(seen.Body);
        Assert.Contains("\"size\":5000", text, StringComparison.Ordinal);
        Assert.Contains("\"magic\":\"zip\"", text, StringComparison.Ordinal);
        Assert.Contains(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(big)).ToLowerInvariant(), text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task When_the_core_says_too_large_the_file_is_described_instead()
    {
        using var dir = new TestDir();
        var fake = new FakeCore { Respond = s => s.Path == "/v1/files/analyze" ? new HttpResponseMessage(HttpStatusCode.RequestEntityTooLarge) : FakeCore.Json(FakeCore.Suspicious) };
        using var rig = new Rig(dir.Path, fake);
        rig.Start();
        rig.Write("a.pdf", Pdf);
        await Wait.Until(() => rig.Judged == 1, "a verdict");
        Assert.Single(fake.To("/v1/files/analyze"));
        Assert.Single(fake.To("/v1/files/check"));
    }

    [Fact]
    public async Task While_the_core_is_down_files_wait_and_are_judged_once_when_it_returns()
    {
        using var dir = new TestDir();
        var down = true;
        var fake = new FakeCore();
        fake.Respond = _ => down ? throw new HttpRequestException("refused") : FakeCore.Json(FakeCore.Suspicious);
        using var rig = new Rig(dir.Path, fake);
        rig.Start();
        rig.Write("one.pdf", Pdf);
        rig.Write("two.pdf", Pdf.Concat(new byte[] { 1 }).ToArray());
        await Wait.Until(() => !fake.Requests.IsEmpty, "a first attempt");
        await Task.Delay(300);
        Assert.Equal(0, rig.Judged);
        Assert.Equal(2, rig.Spool.Snapshot().Count);
        Assert.Contains(rig.Log.Messages, m => m.Contains("not answering", StringComparison.Ordinal));

        down = false;
        await Wait.Until(() => rig.Judged == 2, "both verdicts after the core came back");
        await Task.Delay(300);
        Assert.Equal(2, rig.Judged);
        Assert.Equal(new[] { "one.pdf", "two.pdf" }, rig.Outcomes.Select(o => o.Event.Name).Order().ToArray());
        Assert.Empty(rig.Spool.Snapshot());
    }

    [Fact]
    public async Task A_wrong_token_keeps_files_waiting_and_is_never_a_verdict()
    {
        using var dir = new TestDir();
        var fake = new FakeCore { Respond = _ => new HttpResponseMessage(HttpStatusCode.Unauthorized) };
        using var rig = new Rig(dir.Path, fake);
        rig.Start();
        rig.Write("a.pdf", Pdf);
        await Wait.Until(() => !fake.Requests.IsEmpty, "an attempt");
        await Task.Delay(300);
        Assert.Equal((0, 1), (rig.Judged, rig.Spool.Snapshot().Count));
    }

    [Fact]
    public async Task A_restart_neither_repeats_judged_files_nor_misses_ones_added_while_stopped()
    {
        using var dir = new TestDir();
        var fake = new FakeCore();
        var rig = new Rig(dir.Path, fake);
        rig.Start();
        rig.Write("a.pdf", Pdf);
        rig.Write("b.pdf", Pdf.Concat(new byte[] { 2 }).ToArray());
        await Wait.Until(() => rig.Judged == 2, "two verdicts");
        await rig.StopAsync();
        rig.Dispose();

        File.WriteAllBytes(Path.Combine(dir.Path, "watched", "c.pdf"), Pdf.Concat(new byte[] { 3 }).ToArray());
        using var second = new Rig(dir.Path, fake);
        second.Start();
        await Wait.Until(() => second.Judged == 1, "the file added while stopped");
        await Task.Delay(500);
        Assert.Equal("c.pdf", Assert.Single(second.Outcomes).Event.Name);
        var names = fake.To("/v1/files/analyze").Select(r => r.Name).Order().ToArray();
        Assert.Equal(new[] { "a.pdf", "b.pdf", "c.pdf" }, names);
    }

    [Fact]
    public async Task A_burst_of_a_thousand_files_is_all_judged_once_even_if_the_watcher_overflows()
    {
        using var dir = new TestDir();
        using var rig = new Rig(dir.Path, tweak: c => c with { WatcherBufferBytes = 4096, StableMillis = 150 });
        rig.Start();
        for (var i = 0; i < 1000; i++)
        {
            rig.Write($"f{i:D4}.bin", Encoding.ASCII.GetBytes("file number " + i));
        }

        var clock = Stopwatch.StartNew();
        await Wait.Until(() => rig.Judged >= 1000, "a thousand verdicts", 90_000);
        await Task.Delay(500);
        var names = rig.Fake.To("/v1/files/analyze").Select(r => r.Name).ToList();
        Assert.Equal(1000, names.Count);
        Assert.Equal(1000, names.Distinct().Count());
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(90));
    }

    [Fact]
    public async Task A_lost_event_is_found_by_a_rescan()
    {
        using var dir = new TestDir();
        using var rig = new Rig(dir.Path);
        File.WriteAllBytes(Path.Combine(rig.Watched, "early.pdf"), Pdf);
        var future = DateTimeOffset.UtcNow.AddMinutes(-1);
        rig.Pipeline.Rescan(future);
        rig.Start();
        await Wait.Until(() => rig.Judged == 1, "the found file");
        rig.Pipeline.OnWatcherError(rig.Watched, new InternalBufferOverflowException());
        await Task.Delay(300);
        Assert.Equal(1, Analyzed(rig));
    }

    [Fact]
    public async Task A_junction_is_not_followed()
    {
        using var dir = new TestDir();
        var outside = dir.Sub("outside");
        File.WriteAllBytes(Path.Combine(outside, "secret.pdf"), Pdf);
        using var rig = new Rig(dir.Path, tweak: c => c with { IncludeSubfolders = true });
        var link = Path.Combine(rig.Watched, "link");
        var made = Process.Start(new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{outside}\"") { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true });
        await made!.WaitForExitAsync();
        Assert.True(Directory.Exists(link), "the junction could not be created");
        try
        {
            rig.Start();
            rig.Write("real.pdf", Pdf);
            await Wait.Until(() => rig.Judged == 1, "the real file");
            rig.Pipeline.Touch(Path.Combine(link, "secret.pdf"));
            File.WriteAllBytes(Path.Combine(link, "new.pdf"), Pdf.Concat(new byte[] { 9 }).ToArray());
            await Task.Delay(600);
            Assert.Equal(new[] { "real.pdf" }, rig.Fake.To("/v1/files/analyze").Select(r => r.Name).ToArray());
        }
        finally
        {
            Directory.Delete(link);
        }
    }

    [Fact]
    public async Task Hostile_names_are_handled_and_never_crash_the_agent()
    {
        using var dir = new TestDir();
        using var rig = new Rig(dir.Path);
        rig.Start();
        var names = new List<string> { "invoice‮fdp.exe", new string('a', 240) + ".exe", "😀 unicode.pdf", "plain.pdf" };
        var created = 0;
        foreach (var name in names)
        {
            File.WriteAllBytes(Path.Combine(rig.Watched, name), Pdf.Concat(Encoding.UTF8.GetBytes(name)).ToArray());
            created++;
        }

        try
        {
            File.WriteAllBytes(Path.Combine(rig.Watched, "lone\uD800surrogate.pdf"), Pdf.Concat(new byte[] { 7 }).ToArray());
            created++;
        }
        catch (Exception e) when (e is IOException or ArgumentException)
        {
            // the file system refused that name; the others still count
        }

        // an antivirus may block a name like the right-to-left one outright: that file is then skipped, not judged
        await Wait.Until(() => rig.Judged + rig.Pipeline.Stats.Skipped == created, "every hostile name judged or skipped");
        var sent = rig.Fake.To("/v1/files/analyze").Select(r => r.Name).ToList();
        Assert.Contains("😀 unicode.pdf", sent);
        Assert.Contains(sent, n => n!.Length == 244);
        Assert.Equal(created, sent.Count + (int)rig.Pipeline.Stats.Skipped);
    }

    [Fact]
    public async Task A_waiting_file_that_was_deleted_is_recorded_as_gone_not_judged()
    {
        using var dir = new TestDir();
        using var rig = new Rig(dir.Path);
        var path = Path.Combine(rig.Watched, "gone.pdf");
        rig.Spool.TryAdd(new FileEvent("gone", path, "gone.pdf", 5, 1, DateTimeOffset.UtcNow));
        Assert.True(await rig.Pipeline.DeliverOneAsync(CancellationToken.None));
        Assert.Empty(rig.Spool.Snapshot());
        Assert.Equal(1, rig.Pipeline.Stats.Vanished);
        Assert.Empty(rig.Fake.Requests);
    }

    [Fact]
    public async Task A_core_error_verdict_is_retried_a_few_times_then_given_up_on_and_never_called_safe()
    {
        using var dir = new TestDir();
        var fake = new FakeCore { Respond = _ => FakeCore.Json(FakeCore.Verdict("ERROR")) };
        using var rig = new Rig(dir.Path, fake);
        rig.Start();
        rig.Write("a.pdf", Pdf);
        await Wait.Until(() => rig.Pipeline.Stats.GaveUp == 1, "give up");
        Assert.Equal(3, fake.To("/v1/files/analyze").Count);
        Assert.All(rig.Outcomes, o => Assert.Equal("ERROR", o.Verdict.State));
        Assert.Empty(rig.Spool.Snapshot());
    }

    [Fact]
    public async Task A_refused_file_is_recorded_as_an_error_and_not_retried_forever()
    {
        using var dir = new TestDir();
        var fake = new FakeCore { Respond = _ => new HttpResponseMessage(HttpStatusCode.UnprocessableEntity) };
        using var rig = new Rig(dir.Path, fake);
        rig.Start();
        rig.Write("a.pdf", Pdf);
        await Wait.Until(() => rig.Pipeline.Stats.Errors == 1, "an error");
        await Task.Delay(300);
        Assert.Equal((1, 0), (Analyzed(rig), rig.Spool.Snapshot().Count));
    }

    [Fact]
    public async Task The_origin_host_is_sent_but_no_url_is_logged_or_queued()
    {
        using var dir = new TestDir();
        using var rig = new Rig(dir.Path);
        rig.Start();
        var path = rig.Write("FILEMARK.pdf", Pdf);
        File.WriteAllText(path + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://page.test/REFMARK?r=REFQUERY\r\nHostUrl=https://origin.test/PATHMARK?q=QUERYMARK#FRAGMARK\r\n");
        // the stream is written after the file; touch again so the finished file is read with it
        File.SetLastWriteTimeUtc(path, DateTime.UtcNow);
        await Wait.Until(() => rig.Judged == 1, "a verdict");

        var seen = Assert.Single(rig.Fake.To("/v1/files/analyze"));
        Assert.Equal("origin.test", seen.Host);
        var text = string.Join("\n", rig.Log.Messages) + File.ReadAllText(Path.Combine(dir.Path, "data", "spool.jsonl"));
        foreach (var secret in new[] { "PATHMARK", "QUERYMARK", "FRAGMARK", "REFMARK", "REFQUERY", "FILEMARK", "page.test", "origin.test" })
        {
            Assert.DoesNotContain(secret, text, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task A_second_pipeline_run_with_the_same_files_judges_nothing_twice()
    {
        using var dir = new TestDir();
        var fake = new FakeCore();
        var first = new Rig(dir.Path, fake);
        first.Start();
        first.Write("a.pdf", Pdf);
        await Wait.Until(() => first.Judged == 1, "first verdict");
        await first.StopAsync();
        first.Dispose();

        using var second = new Rig(dir.Path, fake);
        second.Start();
        await Task.Delay(800);
        Assert.Equal((0, 1), (second.Judged, fake.To("/v1/files/analyze").Count));
    }
}
