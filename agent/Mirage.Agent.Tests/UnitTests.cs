using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace Mirage.Agent.Tests;

public class FileSignaturesTests
{
    public static TheoryData<string> Names()
    {
        var data = new TheoryData<string>();
        foreach (var c in Cases())
        {
            data.Add(c.GetProperty("name").GetString()!);
        }

        return data;
    }

    private static List<JsonElement> Cases()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "filetypes.json")));
        return [.. document.RootElement.GetProperty("cases").EnumerateArray().Select(e => e.Clone())];
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void The_detector_agrees_with_the_shared_fixture(string name)
    {
        var c = Cases().Single(e => e.GetProperty("name").GetString() == name);
        var body = c.TryGetProperty("hex", out var hex) ? Convert.FromHexString(hex.GetString()!.Replace(" ", "", StringComparison.Ordinal)) : Encoding.UTF8.GetBytes(c.GetProperty("text").GetString()!);
        var at = c.TryGetProperty("at", out var offset) ? offset.GetInt32() : 0;
        var data = new byte[at + body.Length];
        body.CopyTo(data, at);
        var expected = c.GetProperty("expect").ValueKind == JsonValueKind.Null ? null : c.GetProperty("expect").GetString();
        Assert.Equal(expected, FileSignatures.Detect(data));
    }

    [Fact]
    public void The_fixture_is_not_empty() => Assert.True(Cases().Count > 30);
}

public class MarkOfTheWebTests
{
    [Theory]
    [InlineData("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://page.test/a?x=1\r\nHostUrl=https://files.test/dl/a.zip?token=SECRET#frag\r\n", "files.test")]
    [InlineData("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://Page.TEST./a?x=1\r\n", "page.test")]
    [InlineData("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=about:internet\r\nReferrerUrl=https://page.test/\r\n", "page.test")]
    [InlineData("hosturl=http://UPPER.test/x\n", "upper.test")]
    [InlineData("HostUrl=ftp://files.test/a\n", null)]
    [InlineData("HostUrl=file:///C:/a.zip\n", null)]
    [InlineData("HostUrl=https://[::1]/a\n", null)]
    [InlineData("HostUrl=not a url\n", null)]
    [InlineData("ZoneId=3\n", null)]
    [InlineData("", null)]
    [InlineData("HostUrl=https://exa mple.test/\n", null)]
    public void Only_the_host_comes_out(string content, string? host)
    {
        var result = MarkOfTheWeb.HostFrom(content);
        Assert.Equal(host, result);
        Assert.DoesNotContain("SECRET", result ?? "", StringComparison.Ordinal);
    }

    [Fact]
    public void A_real_stream_is_read_and_a_missing_one_is_null()
    {
        using var dir = new TestDir();
        var path = Path.Combine(dir.Path, "a.bin");
        File.WriteAllBytes(path, [1, 2, 3]);
        Assert.Null(MarkOfTheWeb.OriginHost(path));
        File.WriteAllText(path + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://origin.test/p?q=SECRET\r\n");
        Assert.Equal("origin.test", MarkOfTheWeb.OriginHost(path));
        Assert.Null(MarkOfTheWeb.OriginHost(Path.Combine(dir.Path, "missing.bin")));
    }

    [Fact]
    public void A_huge_stream_is_cut_not_trusted()
    {
        using var dir = new TestDir();
        var path = Path.Combine(dir.Path, "a.bin");
        File.WriteAllBytes(path, [1]);
        File.WriteAllText(path + ":Zone.Identifier", new string('x', 100_000) + "\nHostUrl=https://late.test/\n");
        Assert.Null(MarkOfTheWeb.OriginHost(path));
    }
}

public class ConfigTests
{
    [Fact]
    public void Defaults_are_valid_and_a_missing_file_gives_them()
    {
        new AgentConfig().Validate();
        using var dir = new TestDir();
        var loaded = AgentConfig.Load(Path.Combine(dir.Path, "none.json"));
        Assert.Equal(("http://127.0.0.1:8765", 1000, null), (loaded.CoreUrl, loaded.StableMillis, loaded.CoreCommand));
        Assert.Equal(new AgentConfig().CoreArgs, loaded.CoreArgs);
    }

    [Theory]
    [InlineData("""{"CoreUrl":"http://example.com:8765"}""")]
    [InlineData("""{"CoreUrl":"http://10.0.0.5:8765"}""")]
    [InlineData("""{"CoreUrl":"https://127.0.0.1:8765"}""")]
    [InlineData("""{"CoreUrl":"http://user:pw@127.0.0.1:8765"}""")] // pragma: allowlist secret
    [InlineData("""{"Unknown":1}""")]
    [InlineData("""{"WatchFolders":["relative\\dir"]}""")]
    [InlineData("""{"StableMillis":1}""")]
    [InlineData("""{"MaxAttempts":0}""")]
    [InlineData("""{"RetryBaseMillis":500,"RetryMaxMillis":10}""")]
    [InlineData("not json")]
    [InlineData("null")]
    public void A_config_it_cannot_trust_is_refused(string json)
    {
        using var dir = new TestDir();
        var path = Path.Combine(dir.Path, "agent.json");
        File.WriteAllText(path, json);
        Assert.Throws<ConfigException>(() => AgentConfig.Load(path));
    }

    [Fact]
    public void Comments_and_trailing_commas_are_allowed_and_values_are_read()
    {
        using var dir = new TestDir();
        var path = Path.Combine(dir.Path, "agent.json");
        File.WriteAllText(path, "{ // note\n \"coreUrl\": \"http://[::1]:9000\", \"stableMillis\": 500, }");
        var config = AgentConfig.Load(path);
        Assert.Equal((500, "http://[::1]:9000"), (config.StableMillis, config.CoreUrl));
    }

    [Fact]
    public void A_config_over_64_KiB_is_refused()
    {
        using var dir = new TestDir();
        var path = Path.Combine(dir.Path, "agent.json");
        File.WriteAllText(path, "{\"CoreUrl\":\"http://127.0.0.1:1\"," + new string(' ', 70_000) + "}");
        Assert.Throws<ConfigException>(() => AgentConfig.Load(path));
    }
}

public class CoreHttpTests
{
    [Theory]
    [InlineData("http://127.0.0.1:8765", true)]
    [InlineData("http://localhost:8765", true)]
    [InlineData("http://LOCALHOST", true)]
    [InlineData("http://[::1]:8765", true)]
    [InlineData("http://127.1.2.3", true)]
    [InlineData("http://example.com", false)]
    [InlineData("http://localhost.evil.test", false)]
    [InlineData("http://10.0.0.1", false)]
    [InlineData("http://169.254.169.254", false)]
    [InlineData("https://127.0.0.1", false)]
    [InlineData("http://127.0.0.1@evil.test/", false)]
    [InlineData("http://user@127.0.0.1/", false)]
    public void Only_this_machine_is_a_core_address(string url, bool allowed) =>
        Assert.Equal(allowed, CoreHttp.IsLoopbackUrl(new Uri(url)));

    [Fact]
    public void A_client_for_another_machine_cannot_be_made() =>
        Assert.Throws<ArgumentException>(() => CoreHttp.Create(new Uri("http://example.com"), TimeSpan.FromSeconds(1)));

    [Fact]
    public async Task The_real_client_reaches_a_local_server_and_does_not_follow_a_redirect()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var requests = new List<string>();
        var server = Task.Run(async () =>
        {
            for (var i = 0; i < 2; i++)
            {
                using var client = await listener.AcceptTcpClientAsync();
                var stream = client.GetStream();
                var received = new MemoryStream();
                var buffer = new byte[16384];
                var headerEnd = -1;
                var wanted = 0;
                while (headerEnd < 0 || received.Length < headerEnd + wanted)
                {
                    var read = await stream.ReadAsync(buffer);
                    if (read == 0)
                    {
                        break;
                    }

                    received.Write(buffer, 0, read);
                    var text = Encoding.Latin1.GetString(received.ToArray());
                    headerEnd = text.IndexOf("\r\n\r\n", StringComparison.Ordinal) is var h and >= 0 ? h + 4 : -1;
                    if (headerEnd > 0)
                    {
                        var marker = text.IndexOf("Content-Length: ", StringComparison.OrdinalIgnoreCase);
                        wanted = marker < 0 ? 0 : int.Parse(text[(marker + 16)..text.IndexOf('\r', marker)], System.Globalization.CultureInfo.InvariantCulture);
                    }
                }

                requests.Add(Encoding.Latin1.GetString(received.ToArray()));
                var response = i == 0
                    ? "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + FakeCore.Suspicious.Length + "\r\nConnection: close\r\n\r\n" + FakeCore.Suspicious
                    : "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                await stream.WriteAsync(Encoding.ASCII.GetBytes(response));
            }
        });
        using var http = CoreHttp.Create(new Uri($"http://127.0.0.1:{port}"), TimeSpan.FromSeconds(5));
        var core = new CoreClient(http, () => "wire-token", verifyCore: false);
        var first = await core.AnalyzeAsync("a.pdf", new string('a', 64), "origin.test", new byte[] { 1, 2, 3 }, CancellationToken.None);
        var second = await core.AnalyzeAsync("a.pdf", new string('a', 64), null, new byte[] { 1 }, CancellationToken.None);
        await server;
        listener.Stop();
        Assert.True(first.Status == CoreStatus.Ok, first.Detail);
        Assert.Equal("SUSPICIOUS", first.Verdict!.State);
        Assert.Contains("Authorization: Bearer wire-token", requests[0], StringComparison.Ordinal);
        Assert.Contains("X-Mirage-Origin-Host: origin.test", requests[0], StringComparison.Ordinal);
        Assert.Equal(CoreStatus.Rejected, second.Status);
        Assert.Equal(2, requests.Count);
    }
}

public class CoreClientTests
{
    private static (CoreClient Client, FakeCore Fake) Make(Func<string?>? token = null)
    {
        var fake = new FakeCore();
        return (new CoreClient(new HttpClient(fake) { BaseAddress = new Uri("http://127.0.0.1:8765") }, token ?? (() => "t0k"), verifyCore: false), fake);
    }

    [Fact]
    public async Task A_file_is_sent_as_bytes_with_its_facts_in_headers()
    {
        var (client, fake) = Make();
        var result = await client.AnalyzeAsync("Ünï cödé #1.pdf", new string('b', 64), "origin.test", new byte[] { 9, 8, 7 }, CancellationToken.None);
        var seen = Assert.Single(fake.Requests);
        Assert.Equal(("/v1/files/analyze", "Ünï cödé #1.pdf", "origin.test", "Bearer t0k", "application/octet-stream"), (seen.Path, seen.Name, seen.Host, seen.Auth, seen.ContentType));
        Assert.Equal(new byte[] { 9, 8, 7 }, seen.Body);
        Assert.Equal((CoreStatus.Ok, "SUSPICIOUS", 60), (result.Status, result.Verdict!.State, result.Verdict.RiskScore));
        Assert.Equal(["email.pdf_javascript"], result.Verdict.Rules);
    }

    [Fact]
    public async Task A_description_is_json_and_carries_no_contents()
    {
        var (client, fake) = Make();
        await client.CheckAsync("big.iso", 5_000_000_000, new string('c', 64), "iso", null, CancellationToken.None);
        var seen = Assert.Single(fake.Requests);
        using var body = JsonDocument.Parse(seen.Body);
        Assert.Equal("/v1/files/check", seen.Path);
        Assert.Equal(("big.iso", 5_000_000_000, "iso", JsonValueKind.Null), (body.RootElement.GetProperty("name").GetString(), body.RootElement.GetProperty("size").GetInt64(), body.RootElement.GetProperty("magic").GetString(), body.RootElement.GetProperty("origin_host").ValueKind));
    }

    [Theory]
    [InlineData(401, CoreStatus.Unauthorized)]
    [InlineData(403, CoreStatus.Unauthorized)]
    [InlineData(413, CoreStatus.TooLarge)]
    [InlineData(408, CoreStatus.Unavailable)]
    [InlineData(429, CoreStatus.Unavailable)]
    [InlineData(500, CoreStatus.Unavailable)]
    [InlineData(503, CoreStatus.Unavailable)]
    [InlineData(400, CoreStatus.Rejected)]
    [InlineData(415, CoreStatus.Rejected)]
    [InlineData(422, CoreStatus.Rejected)]
    [InlineData(302, CoreStatus.Rejected)]
    public async Task Each_status_maps_to_one_outcome_and_none_is_a_verdict(int code, CoreStatus expected)
    {
        var (client, fake) = Make();
        fake.Respond = _ => new HttpResponseMessage((HttpStatusCode)code);
        var result = await client.AnalyzeAsync("a", new string('a', 64), null, new byte[] { 1 }, CancellationToken.None);
        Assert.Equal(expected, result.Status);
        Assert.Null(result.Verdict);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("{}")]
    [InlineData("""{"verdict":{}}""")]
    [InlineData("""{"verdict":{"state":"SAFE"}}""")]
    [InlineData("""{"verdict":{"state":"benign"}}""")]
    [InlineData("""{"verdict":{"state":null}}""")]
    [InlineData("""[1,2]""")]
    public async Task A_garbled_or_invented_answer_is_never_taken_as_a_verdict(string body)
    {
        var (client, fake) = Make();
        fake.Respond = _ => FakeCore.Json(body);
        var result = await client.CheckAsync("a", 1, new string('a', 64), null, null, CancellationToken.None);
        Assert.Equal(CoreStatus.Rejected, result.Status);
    }

    [Fact]
    public async Task An_oversize_answer_is_refused()
    {
        var (client, fake) = Make();
        fake.Respond = _ => FakeCore.Json("{\"verdict\":{\"state\":\"UNKNOWN\"},\"pad\":\"" + new string('x', 1_100_000) + "\"}");
        Assert.Equal(CoreStatus.Rejected, (await client.CheckAsync("a", 1, new string('a', 64), null, null, CancellationToken.None)).Status);
    }

    [Fact]
    public async Task No_token_means_nothing_is_sent()
    {
        var (client, fake) = Make(() => null);
        var result = await client.AnalyzeAsync("a", new string('a', 64), null, new byte[] { 1 }, CancellationToken.None);
        Assert.Equal(CoreStatus.Unauthorized, result.Status);
        Assert.Empty(fake.Requests);
    }

    [Fact]
    public async Task A_network_failure_is_unavailable_not_a_verdict()
    {
        var (client, fake) = Make();
        fake.Respond = _ => throw new HttpRequestException("refused");
        Assert.Equal(CoreStatus.Unavailable, (await client.CheckAsync("a", 1, new string('a', 64), null, null, CancellationToken.None)).Status);
    }

    [Fact]
    public async Task A_cancelled_request_is_cancelled_not_unavailable()
    {
        var (client, _) = Make();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.CheckAsync("a", 1, new string('a', 64), null, null, cts.Token));
    }

    [Fact]
    public void Names_the_core_would_reject_are_made_safe()
    {
        Assert.Equal("a\uFFFDb.txt", CoreClient.Clean("a\uD800b.txt"));
        Assert.Equal("a\uFFFDb", CoreClient.Clean("a\0b"));
        Assert.Equal("😀.txt", CoreClient.Clean("😀.txt"));
        var cut = CoreClient.Clean(new string('x', 3000) + ".exe");
        Assert.Equal((1000, true), (cut.Length, cut.EndsWith(".exe", StringComparison.Ordinal)));
    }
}

public class SpoolTests
{
    private static FileEvent Event(string id, string path = @"C:\Users\x\Downloads\a.pdf") =>
        new(id, path, Path.GetFileName(path), 10, 20, DateTimeOffset.UtcNow);

    [Fact]
    public void An_event_is_added_once_and_survives_a_restart_until_it_is_done()
    {
        using var dir = new TestDir();
        var file = Path.Combine(dir.Path, "spool.jsonl");
        var spool = new Spool(file, 100, 1000);
        Assert.True(spool.TryAdd(Event("a")));
        Assert.False(spool.TryAdd(Event("a")));
        Assert.True(spool.TryAdd(Event("b")));
        spool.Complete("a", "UNKNOWN");
        Assert.False(spool.TryAdd(Event("a")));

        var again = new Spool(file, 100, 1000);
        Assert.Equal(["b"], again.Snapshot().Select(e => e.Id));
        Assert.False(again.TryAdd(Event("a")));
        Assert.False(again.TryAdd(Event("b")));
        Assert.True(again.Knows("a"));
    }

    [Fact]
    public void A_torn_last_line_and_junk_are_counted_and_skipped()
    {
        using var dir = new TestDir();
        var file = Path.Combine(dir.Path, "spool.jsonl");
        var spool = new Spool(file, 100, 1000);
        spool.TryAdd(Event("a"));
        File.AppendAllText(file, "garbage\n{\"t\":\"add\",\"id\":\"zz\",\"p\":\"!!!\"}\n{\"t\":\"unknown\",\"id\":\"q\"}\n{\"t\":\"add\",\"id\":\"half");
        var again = new Spool(file, 100, 1000);
        Assert.Equal(["a"], again.Snapshot().Select(e => e.Id));
        Assert.True(again.Stats.Corrupt >= 3);
    }

    [Fact]
    public void When_full_the_oldest_is_dropped_and_the_loss_is_kept()
    {
        using var dir = new TestDir();
        var file = Path.Combine(dir.Path, "spool.jsonl");
        var spool = new Spool(file, 3, 1000);
        foreach (var id in new[] { "a", "b", "c", "d", "e" })
        {
            spool.TryAdd(Event(id));
        }

        Assert.Equal(["c", "d", "e"], spool.Snapshot().Select(e => e.Id));
        Assert.Equal(2, spool.Stats.Dropped);
        var again = new Spool(file, 3, 1000);
        Assert.Equal(["c", "d", "e"], again.Snapshot().Select(e => e.Id));
        Assert.Equal(2, again.Stats.Dropped);
        Assert.False(again.TryAdd(Event("a"))); // dropped, and not silently resurrected
    }

    [Fact]
    public void The_list_of_known_events_is_bounded()
    {
        using var dir = new TestDir();
        var spool = new Spool(Path.Combine(dir.Path, "spool.jsonl"), 100, 3);
        foreach (var id in new[] { "a", "b", "c", "d", "e" })
        {
            spool.TryAdd(Event(id));
            spool.Complete(id, "UNKNOWN");
        }

        Assert.False(spool.Knows("a"));
        Assert.True(spool.Knows("e"));
    }

    [Fact]
    public void A_path_with_an_unpaired_surrogate_round_trips_exactly()
    {
        using var dir = new TestDir();
        var file = Path.Combine(dir.Path, "spool.jsonl");
        var path = @"C:\dl\a" + '\uD800' + "b" + '\u202E' + "fdp.exe";
        new Spool(file, 10, 10).TryAdd(Event("s", path));
        var back = Assert.Single(new Spool(file, 10, 10).Snapshot());
        Assert.Equal(path, back.Path);
    }

    [Fact]
    public void A_deferred_event_is_not_due_until_its_time()
    {
        using var dir = new TestDir();
        var spool = new Spool(Path.Combine(dir.Path, "spool.jsonl"), 10, 10);
        spool.TryAdd(Event("a"));
        spool.TryAdd(Event("b"));
        var now = DateTimeOffset.UtcNow;
        spool.Defer("a", now.AddMinutes(1));
        Assert.Equal("b", spool.NextDue(now)!.Id);
        Assert.Equal("a", spool.NextDue(now.AddMinutes(2))!.Id);
    }

    [Fact]
    public void Many_lines_trigger_a_rewrite_that_keeps_what_is_waiting()
    {
        using var dir = new TestDir();
        var file = Path.Combine(dir.Path, "spool.jsonl");
        var spool = new Spool(file, 100, 50);
        spool.TryAdd(Event("keep"));
        for (var i = 0; i < 2600; i++)
        {
            spool.TryAdd(Event("e" + i));
            spool.Complete("e" + i, "UNKNOWN");
        }

        var lines = File.ReadAllLines(file).Length;
        Assert.True(lines < 5200, "the file was rewritten: " + lines);
        Assert.Equal(["keep"], new Spool(file, 100, 50).Snapshot().Select(e => e.Id));
    }

    [Fact]
    public void The_spool_holds_no_url_and_no_content()
    {
        using var dir = new TestDir();
        var file = Path.Combine(dir.Path, "spool.jsonl");
        new Spool(file, 10, 10).TryAdd(Event("a"));
        var text = File.ReadAllText(file);
        Assert.DoesNotContain("http", text, StringComparison.OrdinalIgnoreCase);
    }
}

public class NameTests
{
    [Theory]
    [InlineData("a.crdownload", true)]
    [InlineData("A.CRDOWNLOAD", true)]
    [InlineData("a.tmp", true)]
    [InlineData("a.part", true)]
    [InlineData("~$report.docx", true)]
    [InlineData("backup~", true)]
    [InlineData("a.zip:Zone.Identifier", true)]
    [InlineData("a.zip", false)]
    [InlineData("setup.exe", false)]
    [InlineData("tmp", false)]
    public void Temporary_names_are_recognised(string name, bool temporary) =>
        Assert.Equal(temporary, FilePipeline.IsTemporaryName(name));

    [Fact]
    public void An_event_id_depends_on_path_size_and_time_only()
    {
        var id = FilePipeline.EventId(@"C:\D\A.pdf", 5, 7);
        Assert.Equal(id, FilePipeline.EventId(@"c:\d\a.pdf", 5, 7));
        Assert.NotEqual(id, FilePipeline.EventId(@"C:\D\A.pdf", 6, 7));
        Assert.NotEqual(id, FilePipeline.EventId(@"C:\D\A.pdf", 5, 8));
        Assert.Equal(32, id.Length);
    }
}
