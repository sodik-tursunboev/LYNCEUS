using System.Net;

namespace Mirage.Agent.Tests;

public class MailboxWatcherTests
{
    private static string Status(string state, params (double At, string State, int? Score, string[] Rules)[] flagged)
    {
        var items = string.Join(",", flagged.Select(f =>
            $$"""{"at":{{f.At.ToString(System.Globalization.CultureInfo.InvariantCulture)}},"state":"{{f.State}}","score":{{(f.Score is { } s ? s.ToString(System.Globalization.CultureInfo.InvariantCulture) : "null")}},"rules":[{{string.Join(",", f.Rules.Select(r => "\"" + r + "\""))}}]}"""));
        return $$"""{"state":"{{state}}","last_poll":null,"analysed":0,"flagged":[{{items}}]}""";
    }

    private static (MailboxWatcher Watcher, FakeCore Fake, List<(string Title, string Body)> Shown) Make()
    {
        var fake = new FakeCore();
        var shown = new List<(string, string)>();
        var core = new CoreClient(new HttpClient(fake) { BaseAddress = new Uri("http://127.0.0.1:8765") }, () => "t", verifyCore: false);
        return (new MailboxWatcher(core, shown.Add, new ListLogger()), fake, shown);
    }

    [Fact]
    public async Task The_first_look_is_a_baseline_and_a_new_flagged_mail_is_announced_once()
    {
        var (watcher, fake, shown) = Make();
        fake.Respond = _ => FakeCore.Json(Status("connected", (10, "SUSPICIOUS", 70, ["email.old"])));
        await watcher.PollOnceAsync(CancellationToken.None);
        Assert.Empty(shown);

        fake.Respond = _ => FakeCore.Json(Status("connected", (10, "SUSPICIOUS", 70, ["email.old"]), (20, "MALICIOUS", 93, ["email.link_text_brand_mismatch", "url.combosquat"])));
        await watcher.PollOnceAsync(CancellationToken.None);
        await watcher.PollOnceAsync(CancellationToken.None);
        var one = Assert.Single(shown);
        Assert.Equal("MIRAGE: dangerous email", one.Title);
        Assert.Contains("link text brand mismatch", one.Body, StringComparison.Ordinal);
        Assert.Contains("score 93", one.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("email.link_text_brand_mismatch", one.Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Several_new_mails_are_announced_oldest_first()
    {
        var (watcher, fake, shown) = Make();
        fake.Respond = _ => FakeCore.Json(Status("connected"));
        await watcher.PollOnceAsync(CancellationToken.None);
        fake.Respond = _ => FakeCore.Json(Status("connected", (30, "SUSPICIOUS", 60, ["email.b"]), (20, "MALICIOUS", 90, ["email.a"])));
        await watcher.PollOnceAsync(CancellationToken.None);
        Assert.Equal(["MIRAGE: dangerous email", "MIRAGE: suspicious email"], shown.Select(s => s.Title).ToArray());
    }

    [Fact]
    public async Task A_lost_connection_to_the_core_says_nothing_and_never_claims_the_mailbox_is_clean()
    {
        var (watcher, fake, shown) = Make();
        fake.Respond = _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        await watcher.PollOnceAsync(CancellationToken.None);
        fake.Respond = _ => throw new HttpRequestException("down");
        await watcher.PollOnceAsync(CancellationToken.None);
        Assert.Empty(shown);
    }

    [Fact]
    public async Task Needing_to_reconnect_is_announced_once_until_it_has_been_fixed()
    {
        var (watcher, fake, shown) = Make();
        fake.Respond = _ => FakeCore.Json(Status("reauth_needed"));
        await watcher.PollOnceAsync(CancellationToken.None);
        await watcher.PollOnceAsync(CancellationToken.None);
        Assert.Single(shown);
        Assert.Contains("mailbox", shown[0].Title, StringComparison.Ordinal);
        Assert.Contains("--provider outlook", shown[0].Body, StringComparison.Ordinal);
        fake.Respond = _ => FakeCore.Json(Status("connected"));
        await watcher.PollOnceAsync(CancellationToken.None);
        fake.Respond = _ => FakeCore.Json(Status("reauth_needed"));
        await watcher.PollOnceAsync(CancellationToken.None);
        Assert.Equal(2, shown.Count);
    }

    [Fact]
    public async Task A_disabled_mailbox_is_silent()
    {
        var (watcher, fake, shown) = Make();
        fake.Respond = _ => FakeCore.Json("""{"state":"off"}""");
        await watcher.PollOnceAsync(CancellationToken.None);
        await watcher.PollOnceAsync(CancellationToken.None);
        Assert.Empty(shown);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("{}")]
    [InlineData("""{"state":5}""")]
    [InlineData("""{"state":"connected","flagged":"x"}""")]
    [InlineData("""{"state":"connected","flagged":[{"at":"now","state":"MALICIOUS"},{"state":"MALICIOUS"},5,null]}""")]
    public async Task Hostile_status_answers_are_ignored_without_a_crash_or_an_alert(string body)
    {
        var (watcher, fake, shown) = Make();
        fake.Respond = _ => FakeCore.Json(body);
        await watcher.PollOnceAsync(CancellationToken.None);
        await watcher.PollOnceAsync(CancellationToken.None);
        Assert.Empty(shown);
    }

    [Fact]
    public async Task A_notification_that_fails_does_not_stop_the_watcher()
    {
        var fake = new FakeCore { Respond = _ => FakeCore.Json(Status("connected")) };
        var core = new CoreClient(new HttpClient(fake) { BaseAddress = new Uri("http://127.0.0.1:8765") }, () => "t", verifyCore: false);
        var watcher = new MailboxWatcher(core, _ => throw new InvalidOperationException("toast"), new ListLogger());
        await watcher.PollOnceAsync(CancellationToken.None);
        fake.Respond = _ => FakeCore.Json(Status("connected", (5, "MALICIOUS", 90, ["email.a"])));
        await watcher.PollOnceAsync(CancellationToken.None);
        fake.Respond = _ => FakeCore.Json(Status("connected", (5, "MALICIOUS", 90, ["email.a"]), (6, "MALICIOUS", 91, ["email.b"])));
        await watcher.PollOnceAsync(CancellationToken.None);
    }

    [Fact]
    public void Mail_toast_text_holds_no_address_and_cleans_rule_names()
    {
        var text = ToastText.ForMail(new FlaggedMail(1, "SUSPICIOUS", null, ["email.evil‮\nname"]))!.Value;
        Assert.DoesNotContain('‮', text.Body);
        Assert.DoesNotContain('@', text.Body);
        Assert.Null(ToastText.ForMail(new FlaggedMail(1, "UNKNOWN", null, [])));
        Assert.Contains("several signs", ToastText.ForMail(new FlaggedMail(1, "MALICIOUS", null, []))!.Value.Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_status_request_is_a_get_with_the_token()
    {
        var (watcher, fake, _) = Make();
        fake.Respond = _ => FakeCore.Json(Status("connected"));
        await watcher.PollOnceAsync(CancellationToken.None);
        var seen = Assert.Single(fake.Requests);
        Assert.Equal(("/v1/mailbox/status", "Bearer t"), (seen.Path, seen.Auth));
        Assert.Empty(seen.Body);
    }
}
