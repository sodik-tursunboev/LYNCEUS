using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Lynceus.Agent.Tests;

/// <summary>A pocket version of the core's action endpoints, with the same legal moves.</summary>
public sealed class FakeActionsCore
{
    private static readonly Dictionary<(string, string), string> Next = new()
    {
        [("PENDING", "approve")] = "APPROVED",
        [("APPROVED", "applied")] = "APPLIED",
        [("APPROVED", "failed")] = "FAILED",
        [("APPLIED", "restore")] = "RESTORE_REQUESTED",
        [("RESTORE_REQUESTED", "restored")] = "RESTORED",
        [("RESTORE_REQUESTED", "restore_failed")] = "APPLIED",
    };

    public Dictionary<Guid, (string State, string FileRef, string Sha, string? Reason)> Actions { get; } = [];

    public List<string> Reports { get; } = [];

    public bool FailReports { get; set; }

    /// <summary>Actions the fake core reports as email: the agent must never touch these.</summary>
    public HashSet<Guid> MailActions { get; } = [];

    public FakeCore Handler { get; } = new();

    public FakeActionsCore() => Handler.Respond = Route;

    public Guid Add(string state, string sha, string? fileRef = null)
    {
        var id = Guid.NewGuid();
        Actions[id] = (state, fileRef ?? Guid.NewGuid().ToString("N"), sha, null);
        return id;
    }

    private HttpResponseMessage Route(Seen s)
    {
        if (s.Method == "GET" && s.Path == "/v1/actions")
        {
            var wanted = Uri.UnescapeDataString(s.Query.Split("state=")[1].Split('&')[0]).Split(',');
            var items = Actions.Where(a => wanted.Contains(a.Value.State))
                .Select(a => new { id = a.Key, kind = MailActions.Contains(a.Key) ? "MAIL_QUARANTINE" : "FILE_QUARANTINE", state = a.Value.State, file_ref = a.Value.FileRef, sha256 = a.Value.Sha });
            return FakeCore.Json(JsonSerializer.Serialize(items));
        }

        var parts = s.Path.Split('/');
        if (s.Method == "POST" && parts.Length == 5 && parts[2] == "actions" && Guid.TryParse(parts[3], out var id) && Actions.TryGetValue(id, out var a2))
        {
            var verb = parts[4];
            if (verb == "result")
            {
                using var body = JsonDocument.Parse(s.Body);
                verb = body.RootElement.GetProperty("outcome").GetString()!;
                Reports.Add(verb + ":" + (body.RootElement.TryGetProperty("reason", out var r) && r.ValueKind == JsonValueKind.String ? r.GetString() : ""));
                if (FailReports)
                {
                    return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
                }
            }

            if (!Next.TryGetValue((a2.State, verb), out var next))
            {
                return new HttpResponseMessage(HttpStatusCode.Conflict);
            }

            Actions[id] = a2 with { State = next };
            return FakeCore.Json("{}");
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }
}

public sealed class ResponseFlowTests : IDisposable
{
    private readonly TestDir dir = new();
    private readonly string downloads;
    private readonly string data;
    private readonly FakeActionsCore core = new();
    private readonly List<(string Title, string Body)> toasts = [];
    private readonly List<(string Path, long Size, long Ticks)> restores = [];
    private static readonly byte[] Content = Encoding.ASCII.GetBytes("MZ dangerous " + new string('z', 3000));

    public ResponseFlowTests()
    {
        downloads = dir.Sub("downloads");
        data = dir.Sub("data");
    }

    private static string Sha(byte[] b) => Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();

    public void Dispose()
    {
        dir.Dispose();
        GC.SuppressFinalize(this);
    }

    private sealed class PoisonFs(string poison) : RealFileSystem
    {
        public override FileStream OpenRead(string path) =>
            string.Equals(path, poison, StringComparison.OrdinalIgnoreCase) ? throw new InvalidOperationException("an unexpected failure") : base.OpenRead(path);
    }

    private (ActionRunner Runner, FlaggedStore Flagged, QuarantineStore Quarantine) Make(string mode, RealFileSystem? fs = null)
    {
        var client = new CoreClient(new HttpClient(core.Handler) { BaseAddress = new Uri("http://127.0.0.1:8765") }, () => "t", verifyCore: false);
        var flagged = new FlaggedStore(Path.Combine(data, "flagged.json"));
        var quarantine = new QuarantineStore(Path.Combine(data, "quarantine"), fs);
        return (new ActionRunner(client, flagged, quarantine, mode, toasts.Add, (p, s, t) => restores.Add((p, s, t)), new ListLogger()), flagged, quarantine);
    }

    private (Guid Id, string Path) Flag(FlaggedStore flagged, string state, string name = "bad.exe", byte[]? bytes = null)
    {
        var path = Path.Combine(downloads, name);
        File.WriteAllBytes(path, bytes ?? Content);
        var sha = Sha(bytes ?? Content);
        var id = core.Add(state, sha);
        flagged.Add(id, path, sha, (bytes ?? Content).Length, File.GetLastWriteTimeUtc(path).Ticks);
        return (id, path);
    }

    [Fact]
    public async Task In_ask_mode_a_pending_file_is_announced_once_and_never_touched()
    {
        var (runner, flagged, _) = Make("ask");
        var (id, path) = Flag(flagged, "PENDING");
        for (var i = 0; i < 3; i++)
        {
            await runner.PollOnceAsync(CancellationToken.None);
        }

        Assert.True(File.Exists(path));
        Assert.Equal("PENDING", core.Actions[id].State);
        Assert.Single(toasts);
        Assert.Contains("waiting for your decision", toasts[0].Title, StringComparison.Ordinal);
        Assert.DoesNotContain(core.Handler.Requests, r => r.Method == "POST");
    }

    [Fact]
    public async Task In_auto_mode_the_policy_approves_and_the_next_round_quarantines_and_reports()
    {
        var (runner, flagged, quarantine) = Make("auto");
        var (id, path) = Flag(flagged, "PENDING");
        await runner.PollOnceAsync(CancellationToken.None);
        Assert.Equal("APPROVED", core.Actions[id].State);
        Assert.Equal("policy", core.Handler.Requests.Single(r => r.Path.EndsWith("/approve", StringComparison.Ordinal)).Actor);
        Assert.True(File.Exists(path));

        await runner.PollOnceAsync(CancellationToken.None);
        Assert.False(File.Exists(path));
        Assert.Equal("APPLIED", core.Actions[id].State);
        Assert.Equal(["applied:"], core.Reports);
        Assert.Equal("quarantined", quarantine.Describe(id.ToString("D"))!.Value.State);
    }

    [Fact]
    public async Task A_user_approved_action_is_carried_out_once_even_if_asked_again()
    {
        var (runner, flagged, _) = Make("ask");
        var (id, path) = Flag(flagged, "APPROVED");
        await runner.PollOnceAsync(CancellationToken.None);
        await runner.PollOnceAsync(CancellationToken.None);
        Assert.False(File.Exists(path));
        Assert.Equal(["applied:"], core.Reports);
        Assert.Single(toasts, t => t.Title.Contains("quarantined", StringComparison.Ordinal));
        Assert.Equal("APPLIED", core.Actions[id].State);
    }

    [Fact]
    public async Task A_file_that_changed_since_it_was_judged_is_left_alone_and_the_failure_is_reported()
    {
        var (runner, flagged, _) = Make("ask");
        var (id, path) = Flag(flagged, "APPROVED");
        File.AppendAllText(path, "changed after the verdict");
        await runner.PollOnceAsync(CancellationToken.None);
        Assert.True(File.Exists(path));
        Assert.EndsWith("changed after the verdict", File.ReadAllText(path), StringComparison.Ordinal);
        Assert.Equal(["failed:changed"], core.Reports);
        Assert.Equal("FAILED", core.Actions[id].State);
    }

    [Fact]
    public async Task A_file_that_is_gone_and_an_action_for_a_file_this_agent_never_saw_are_failures_not_crashes()
    {
        var (runner, flagged, _) = Make("ask");
        var (_, path) = Flag(flagged, "APPROVED");
        File.Delete(path);
        var stranger = core.Add("APPROVED", new string('a', 64));
        await runner.PollOnceAsync(CancellationToken.None);
        Assert.Contains("failed:missing", core.Reports);
        Assert.Contains("failed:unknown_file", core.Reports);
        Assert.Equal("FAILED", core.Actions[stranger].State);
    }

    [Fact]
    public async Task Restore_puts_the_file_back_reports_it_and_tells_the_pipeline_not_to_judge_it_again()
    {
        var (runner, flagged, _) = Make("ask");
        var (id, path) = Flag(flagged, "APPROVED");
        var mtime = File.GetLastWriteTimeUtc(path).Ticks;
        await runner.PollOnceAsync(CancellationToken.None);
        core.Actions[id] = core.Actions[id] with { State = "RESTORE_REQUESTED" };
        await runner.PollOnceAsync(CancellationToken.None);
        Assert.Equal(Content, File.ReadAllBytes(path));
        Assert.Equal("RESTORED", core.Actions[id].State);
        Assert.Equal((path, (long)Content.Length, mtime), restores.Single());
        Assert.Contains(toasts, t => t.Title == "Lynceus: file restored");
    }

    [Fact]
    public async Task A_restore_that_cannot_happen_is_reported_and_leaves_the_file_quarantined()
    {
        var (runner, flagged, quarantine) = Make("ask");
        var sub = Path.Combine(downloads, "sub");
        Directory.CreateDirectory(sub);
        var (id, path) = Flag(flagged, "APPROVED", "sub\\bad.exe");
        await runner.PollOnceAsync(CancellationToken.None);
        Directory.Delete(sub);
        core.Actions[id] = core.Actions[id] with { State = "RESTORE_REQUESTED" };
        await runner.PollOnceAsync(CancellationToken.None);
        Assert.Contains("restore_failed:folder_missing", core.Reports);
        Assert.Equal("APPLIED", core.Actions[id].State);
        Assert.False(File.Exists(path));
        Assert.Equal("quarantined", quarantine.Describe(id.ToString("D"))!.Value.State);
        Assert.Empty(restores);
    }

    [Fact]
    public async Task If_the_core_cannot_be_told_the_work_is_not_repeated_and_the_report_is_retried()
    {
        var (runner, flagged, _) = Make("ask");
        var (id, path) = Flag(flagged, "APPROVED");
        core.FailReports = true;
        await runner.PollOnceAsync(CancellationToken.None);
        Assert.False(File.Exists(path));
        Assert.Equal("APPROVED", core.Actions[id].State);
        Assert.DoesNotContain(toasts, t => t.Title.Contains("quarantined", StringComparison.Ordinal));
        core.FailReports = false;
        await runner.PollOnceAsync(CancellationToken.None);
        Assert.Equal("APPLIED", core.Actions[id].State);
        Assert.Single(Directory.GetDirectories(Path.Combine(data, "quarantine")));
        Assert.Single(toasts, t => t.Title.Contains("quarantined", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_core_that_is_down_or_answers_badly_changes_nothing()
    {
        var (runner, flagged, _) = Make("auto");
        var (_, path) = Flag(flagged, "APPROVED");
        core.Handler.Respond = _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        await runner.PollOnceAsync(CancellationToken.None);
        core.Handler.Respond = _ => FakeCore.Json("not json at all");
        await runner.PollOnceAsync(CancellationToken.None);
        core.Handler.Respond = _ => throw new HttpRequestException("down");
        await runner.PollOnceAsync(CancellationToken.None);
        Assert.True(File.Exists(path));
    }

    [Theory]
    [InlineData("APPROVED")]
    [InlineData("PENDING")]
    [InlineData("RESTORE_REQUESTED")]
    public async Task An_email_action_is_never_touched_by_the_agent_in_any_mode(string state)
    {
        foreach (var mode in new[] { "ask", "auto" })
        {
            var (runner, _, _) = Make(mode);
            var mail = core.Add(state, new string('c', 64));
            core.MailActions.Add(mail);
            await runner.PollOnceAsync(CancellationToken.None);
            await runner.PollOnceAsync(CancellationToken.None);
            Assert.Equal(state, core.Actions[mail].State); // not approved by "policy", not failed, not applied
            Assert.Empty(core.Reports);
            Assert.DoesNotContain(core.Handler.Requests, r => r.Method == "POST");
            Assert.All(core.Handler.Requests, r => Assert.Contains("kind=FILE_QUARANTINE", r.Query, StringComparison.Ordinal));
        }
    }

    [Fact]
    public async Task In_off_mode_nothing_is_quarantined_and_nothing_is_approved_or_reported()
    {
        var (runner, flagged, _) = Make("off");
        var (id, path) = Flag(flagged, "APPROVED");
        var pending = Flag(flagged, "PENDING", "other.exe");
        await runner.PollOnceAsync(CancellationToken.None);
        Assert.DoesNotContain(core.Handler.Requests, r => r.Method == "POST");
        Assert.True(File.Exists(path));
        Assert.True(File.Exists(pending.Path));
        Assert.Equal("APPROVED", core.Actions[id].State);
        Assert.Equal("PENDING", core.Actions[pending.Id].State);
    }

    [Fact]
    public async Task In_off_mode_a_restore_you_asked_for_still_happens()
    {
        var (ask, flagged, _) = Make("ask");
        var (id, path) = Flag(flagged, "APPROVED");
        await ask.PollOnceAsync(CancellationToken.None);
        Assert.False(File.Exists(path));
        core.Actions[id] = core.Actions[id] with { State = "RESTORE_REQUESTED" };

        var (off, _, _) = Make("off"); // the owner switched the response mode to off afterwards
        await off.PollOnceAsync(CancellationToken.None);
        Assert.Equal(Content, File.ReadAllBytes(path));
        Assert.Equal("RESTORED", core.Actions[id].State);
    }

    [Fact]
    public async Task One_action_that_throws_does_not_stop_the_others_and_the_core_is_told()
    {
        var poisonPath = Path.Combine(downloads, "poison.exe");
        var (runner, flagged, _) = Make("ask", new PoisonFs(poisonPath)); // opening this one throws, unexpectedly
        var (poisonId, _) = Flag(flagged, "APPROVED", "poison.exe");
        var (goodId, goodPath) = Flag(flagged, "APPROVED", "good.exe", Encoding.ASCII.GetBytes("MZ other " + new string('q', 3000)));

        await runner.PollOnceAsync(CancellationToken.None);

        Assert.True(File.Exists(poisonPath)); // untouched
        Assert.Equal("FAILED", core.Actions[poisonId].State);
        Assert.Contains("failed:io", core.Reports);
        Assert.False(File.Exists(goodPath)); // the other action was carried out in the same round
        Assert.Equal("APPLIED", core.Actions[goodId].State);
    }

    [Fact]
    public async Task A_restore_still_runs_in_a_round_where_another_action_throws()
    {
        var poisonPath = Path.Combine(downloads, "poison.exe");
        var (runner, flagged, _) = Make("ask", new PoisonFs(poisonPath));
        var (doneId, donePath) = Flag(flagged, "APPROVED", "done.exe");
        await runner.PollOnceAsync(CancellationToken.None);
        core.Actions[doneId] = core.Actions[doneId] with { State = "RESTORE_REQUESTED" };
        var (poisonId, _) = Flag(flagged, "APPROVED", "poison.exe", Encoding.ASCII.GetBytes("MZ poison " + new string('p', 3000)));

        await runner.PollOnceAsync(CancellationToken.None);

        Assert.True(File.Exists(donePath));
        Assert.Equal("RESTORED", core.Actions[doneId].State);
        Assert.Equal("FAILED", core.Actions[poisonId].State);
    }

    [Fact]
    public async Task The_agent_never_acts_on_a_pending_action_by_itself_in_ask_mode()
    {
        var (runner, flagged, _) = Make("ask");
        var (id, path) = Flag(flagged, "PENDING");
        await runner.PollOnceAsync(CancellationToken.None);
        Assert.True(File.Exists(path));
        Assert.Equal("PENDING", core.Actions[id].State);
        Assert.Empty(core.Reports);
    }

    // ---- the pieces around it ----------------------------------------------------------------

    [Fact]
    public async Task A_restored_file_is_not_judged_again_when_the_pipeline_is_told_about_it()
    {
        using var rig = new Rig(dir.Sub("rig"));
        var path = rig.Write("back.exe", Content);
        var info = new FileInfo(path);
        rig.Pipeline.Suppress(path, info.Length, info.LastWriteTimeUtc.Ticks);
        rig.Start();
        await Task.Delay(800);
        Assert.Empty(rig.Fake.Requests);
        rig.Write("other.exe", Content.Concat(new byte[] { 1 }).ToArray());
        await Wait.Until(() => rig.Judged == 1, "the other file");
    }

    [Fact]
    public void The_flagged_table_survives_a_restart_remembers_odd_paths_and_announces_once()
    {
        var file = Path.Combine(data, "f.json");
        var store = new FlaggedStore(file);
        var id = Guid.NewGuid();
        var odd = @"C:\dl\a" + '\uD800' + "b\u202Efdp.exe";
        store.Add(id, odd, new string('a', 64), 5, 7);
        store.Add(id, "ignored.exe", new string('b', 64), 1, 1);
        Assert.True(store.FirstAnnouncement(id, "pending"));
        Assert.False(store.FirstAnnouncement(id, "pending"));
        Assert.True(store.FirstAnnouncement(id, "applied"));

        var again = new FlaggedStore(file);
        Assert.Equal((odd, new string('a', 64), 5L, 7L), again.Find(id));
        Assert.False(again.FirstAnnouncement(id, "pending"));
        Assert.Null(again.Find(Guid.NewGuid()));
        Assert.False(again.FirstAnnouncement(Guid.NewGuid(), "pending"));
    }

    [Fact]
    public void The_flagged_table_is_bounded()
    {
        var store = new FlaggedStore(Path.Combine(data, "bounded.json"));
        var first = Guid.NewGuid();
        store.Add(first, "a.exe", new string('a', 64), 1, 1);
        for (var i = 0; i < 520; i++)
        {
            store.Add(Guid.NewGuid(), $"f{i}.exe", new string('a', 64), 1, 1);
        }

        Assert.Null(store.Find(first));
    }

    [Fact]
    public void A_damaged_flagged_file_means_an_empty_table_not_a_crash()
    {
        File.WriteAllText(Path.Combine(data, "bad.json"), "{not json");
        Assert.Null(new FlaggedStore(Path.Combine(data, "bad.json")).Find(Guid.NewGuid()));
    }

    [Fact]
    public async Task The_core_client_sends_the_file_id_and_reads_the_proposed_action_and_the_allow_list_flag()
    {
        var fake = new FakeCore();
        var action = Guid.NewGuid();
        fake.Respond = _ => FakeCore.Json($$"""{"verdict":{"state":"MALICIOUS","risk_score":96,"signals":[]},"inspected":true,"persisted":true,"action_id":"{{action}}","allow_listed":false}""");
        var client = new CoreClient(new HttpClient(fake) { BaseAddress = new Uri("http://127.0.0.1:8765") }, () => "t", verifyCore: false);
        var result = await client.AnalyzeAsync("a.exe", new string('a', 64), null, new byte[] { 1 }, CancellationToken.None, new string('f', 32));
        Assert.Equal((action, false), (result.Verdict!.ActionId, result.Verdict.AllowListed));
        Assert.Equal(new string('f', 32), Assert.Single(fake.Requests).FileId);

        fake.Respond = _ => FakeCore.Json("""{"verdict":{"state":"MALICIOUS","risk_score":96,"signals":[]},"allow_listed":true,"action_id":"not-a-guid"}""");
        var checkedFile = await client.CheckAsync("a.exe", 5, new string('a', 64), null, null, CancellationToken.None, new string('e', 32));
        Assert.Equal((null, true), (checkedFile.Verdict!.ActionId, checkedFile.Verdict.AllowListed));
        using var body = JsonDocument.Parse(fake.Requests.Last().Body);
        Assert.Equal(new string('e', 32), body.RootElement.GetProperty("file_ref").GetString());
    }

    [Fact]
    public void An_allow_listed_file_stays_quiet_and_a_pending_one_says_where_to_decide()
    {
        FileOutcome Outcome(bool allowed, Guid? action) =>
            new(new FileEvent("id", @"C:\x\a.exe", "a.exe", 1, 1, DateTimeOffset.UtcNow), new string('a', 64), null, "exe",
                new FileVerdict("MALICIOUS", 96, [], null, true, true, null, null, ["a reason"], action, allowed));
        Assert.Null(ToastText.ForFile(Outcome(true, null)));
        Assert.Contains("Lynceus console", ToastText.ForFile(Outcome(false, Guid.NewGuid()))!.Value.Body, StringComparison.Ordinal);
        Assert.Contains("Nothing was moved", ToastText.ForFile(Outcome(false, null))!.Value.Body, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("ask", true)]
    [InlineData("auto", true)]
    [InlineData("off", true)]
    [InlineData("Auto", false)]
    [InlineData("yes", false)]
    [InlineData("", false)]
    public void Only_the_three_response_modes_are_accepted(string mode, bool ok)
    {
        var path = Path.Combine(data, "agent.json");
        File.WriteAllText(path, JsonSerializer.Serialize(new { ResponseMode = mode }));
        if (ok)
        {
            Assert.Equal(mode, AgentConfig.Load(path).ResponseMode);
        }
        else
        {
            Assert.Throws<ConfigException>(() => AgentConfig.Load(path));
        }
    }
}
