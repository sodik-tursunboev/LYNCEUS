using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Text;
using System.Text.Json;
using Mirage.Ipc;
using Mirage.NativeHost;

namespace Mirage.Agent.Tests;

public class ProtocolTests
{
    [Theory]
    [InlineData("""{"v":1,"type":"status","id":"a1"}""")]
    [InlineData("""{"v":1,"type":"check_url","id":"n-7.x_y","url":"https://example.test/a?b=c#d"}""")]
    [InlineData("""{"v":1,"type":"override","id":"1","url":"https://example.test/","state":"MALICIOUS","minutes":15}""")]
    [InlineData("""{"v":1,"type":"override","id":"1","url":"https://example.test/"}""")]
    [InlineData("""{"v":1,"type":"hello","secret":"not-the-real-secret-xx"}""")]
    public void Valid_messages_parse(string json)
    {
        Assert.True(Protocol.TryParse(Encoding.UTF8.GetBytes(json), out var request, out var error), error);
        Assert.NotNull(request);
    }

    [Theory]
    [InlineData("not json", "malformed")]
    [InlineData("[]", "malformed")]
    [InlineData("null", "malformed")]
    [InlineData("""{"type":"status","id":"a"}""", "malformed")]
    [InlineData("""{"v":2,"type":"status","id":"a"}""", "malformed")]
    [InlineData("""{"v":"1","type":"status","id":"a"}""", "malformed")]
    [InlineData("""{"v":1,"type":"launch_missiles","id":"a"}""", "unknown_type")]
    [InlineData("""{"v":1,"type":1,"id":"a"}""", "malformed")]
    [InlineData("""{"v":1,"type":"status"}""", "malformed")]
    [InlineData("""{"v":1,"type":"status","id":"a","extra":1}""", "malformed")]
    [InlineData("""{"v":1,"type":"status","id":"a","id":"b"}""", "malformed")]
    [InlineData("""{"v":1,"type":"status","id":"has space"}""", "malformed")]
    [InlineData("""{"v":1,"type":"status","id":""}""", "malformed")]
    [InlineData("""{"v":1,"type":"check_url","id":"a"}""", "malformed")]
    [InlineData("""{"v":1,"type":"check_url","id":"a","url":""}""", "malformed")]
    [InlineData("""{"v":1,"type":"check_url","id":"a","url":5}""", "malformed")]
    [InlineData("""{"v":1,"type":"check_url","id":"a","url":"https://x.test/\u0000"}""", "malformed")]
    [InlineData("""{"v":1,"type":"check_url","id":"a","url":"https://x.test/\n"}""", "malformed")]
    [InlineData("""{"v":1,"type":"override","id":"a","url":"https://x.test/","state":"SAFE"}""", "malformed")]
    [InlineData("""{"v":1,"type":"override","id":"a","url":"https://x.test/","minutes":0}""", "malformed")]
    [InlineData("""{"v":1,"type":"override","id":"a","url":"https://x.test/","minutes":61}""", "malformed")]
    [InlineData("""{"v":1,"type":"override","id":"a","url":"https://x.test/","minutes":1.5}""", "malformed")]
    [InlineData("""{"v":1,"type":"hello","secret":"short"}""", "malformed")]
    [InlineData("""{"v":1,"type":"status","id":"a","x":{"a":{"a":{"a":{"a":1}}}}}""", "malformed")]
    public void Anything_else_is_refused_with_a_code(string json, string code)
    {
        Assert.False(Protocol.TryParse(Encoding.UTF8.GetBytes(json), out var request, out var error));
        Assert.Null(request);
        Assert.Equal(code, error);
    }

    [Fact]
    public void An_oversize_url_is_refused()
    {
        var json = "{\"v\":1,\"type\":\"check_url\",\"id\":\"a\",\"url\":\"https://x.test/" + new string('a', Protocol.MaxUrlChars) + "\"}";
        Assert.False(Protocol.TryParse(Encoding.UTF8.GetBytes(json), out _, out _));
    }

    [Fact]
    public void Replies_carry_the_version_the_type_and_the_id()
    {
        using var document = JsonDocument.Parse(Protocol.Error("q1", "agent_unavailable"));
        var root = document.RootElement;
        Assert.Equal((1, "error", "q1", "agent_unavailable"), (root.GetProperty("v").GetInt32(), root.GetProperty("type").GetString(), root.GetProperty("id").GetString(), root.GetProperty("error").GetString()));
        Assert.True(Protocol.IsHelloReply(Protocol.Hello()));
        Assert.False(Protocol.IsHelloReply(Protocol.Error(null, "x")));
        Assert.False(Protocol.IsHelloReply("{\"type\":\"hello\"}"u8));
    }
}

public class FrameIoTests
{
    private static MemoryStream Bytes(params byte[] bytes) => new(bytes);

    [Fact]
    public async Task A_message_round_trips()
    {
        using var stream = new MemoryStream();
        await FrameIO.WriteAsync(stream, "{\"v\":1}"u8.ToArray(), CancellationToken.None);
        stream.Position = 0;
        Assert.Equal("{\"v\":1}", Encoding.UTF8.GetString((await FrameIO.ReadAsync(stream, CancellationToken.None))!));
        Assert.Null(await FrameIO.ReadAsync(stream, CancellationToken.None));
    }

    [Fact]
    public async Task The_length_is_four_bytes_little_endian_before_the_body()
    {
        using var stream = new MemoryStream();
        await FrameIO.WriteAsync(stream, new byte[] { 7, 8, 9 }, CancellationToken.None);
        Assert.Equal(new byte[] { 3, 0, 0, 0, 7, 8, 9 }, stream.ToArray());
    }

    [Theory]
    [InlineData(new byte[] { 1, 0 })]
    [InlineData(new byte[] { 5, 0, 0, 0, 1, 2 })]
    [InlineData(new byte[] { 0, 0, 0, 0 })]
    [InlineData(new byte[] { 0xff, 0xff, 0xff, 0xff, 1 })]
    [InlineData(new byte[] { 1, 0, 1, 0 })]
    public async Task A_broken_frame_is_an_error_not_a_hang_or_a_huge_allocation(byte[] bytes) =>
        await Assert.ThrowsAsync<FrameException>(() => FrameIO.ReadAsync(Bytes(bytes), CancellationToken.None));

    [Fact]
    public async Task Writing_an_empty_or_oversize_message_is_refused()
    {
        using var stream = new MemoryStream();
        await Assert.ThrowsAsync<FrameException>(() => FrameIO.WriteAsync(stream, ReadOnlyMemory<byte>.Empty, CancellationToken.None));
        await Assert.ThrowsAsync<FrameException>(() => FrameIO.WriteAsync(stream, new byte[FrameIO.MaxFrameBytes + 1], CancellationToken.None));
    }
}

/// <summary>A real pipe server (current-user only) in front of a fake core.</summary>
public sealed class AgentRig : IDisposable
{
    public const string Secret = "test-secret-0123456789abcdef"; // pragma: allowlist secret
    private readonly CancellationTokenSource stop = new();

    public AgentRig(FakeCore? fake = null, string? pipeName = null)
    {
        Fake = fake ?? new FakeCore();
        PipeName = pipeName ?? "mirage-test-" + Guid.NewGuid().ToString("N");
        var core = new CoreClient(new HttpClient(Fake) { BaseAddress = new Uri("http://127.0.0.1:8765") }, () => "t0k", verifyCore: false);
        Server = new PipeServer(PipeName, Secret, new RequestHandler(core, () => new PipelineStats(0, 5, 0, 0, 0, 0, 0, 0, 2, 0)), new ListLogger());
        Run = Task.Run(() => Server.RunAsync(stop.Token));
    }

    public FakeCore Fake { get; }

    public string PipeName { get; }

    public PipeServer Server { get; }

    public Task Run { get; }

    public async Task<NamedPipeClientStream> RawClientAsync()
    {
        var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        await pipe.ConnectAsync(5000);
        return pipe;
    }

    public Task<Stream?> ConnectAsync(CancellationToken ct) => Connector.ConnectAsync(PipeName, Secret, ct);

    public void Dispose()
    {
        stop.Cancel();
        try
        {
            Run.Wait(3000);
        }
        catch (AggregateException)
        {
            // stopping
        }
    }
}

public class PipeServerTests
{
    private static byte[] Json(string text) => Encoding.UTF8.GetBytes(text);

    private static async Task<JsonElement> Ask(Stream pipe, string request)
    {
        await FrameIO.WriteAsync(pipe, Json(request), CancellationToken.None);
        using var cts = new CancellationTokenSource(5000);
        return JsonDocument.Parse((await FrameIO.ReadAsync(pipe, cts.Token))!).RootElement.Clone();
    }

    [Fact]
    public async Task The_right_secret_gets_a_hello_and_then_answers()
    {
        using var rig = new AgentRig();
        await using var pipe = (await rig.ConnectAsync(CancellationToken.None))!;
        var status = await Ask(pipe, """{"v":1,"type":"status","id":"s1"}""");
        Assert.Equal(("status", "s1", "ok", 5, 2), (status.GetProperty("type").GetString(), status.GetProperty("id").GetString(), status.GetProperty("agent").GetString(), status.GetProperty("judged").GetInt32(), status.GetProperty("waiting").GetInt32()));
    }

    [Fact]
    public async Task A_wrong_secret_is_closed_without_an_answer()
    {
        using var rig = new AgentRig();
        await using var pipe = await rig.RawClientAsync();
        await FrameIO.WriteAsync(pipe, Json("""{"v":1,"type":"hello","secret":"wrong-secret-0123456789"}"""), CancellationToken.None);
        using var cts = new CancellationTokenSource(5000);
        Assert.Null(await FrameIO.ReadAsync(pipe, cts.Token));
        await Wait.Until(() => rig.Server.Refused == 1, "a counted refusal");
    }

    [Theory]
    [InlineData("""{"v":1,"type":"status","id":"s1"}""")]
    [InlineData("""{"v":1,"type":"check_url","id":"s1","url":"https://x.test/"}""")]
    [InlineData("garbage")]
    public async Task Anything_but_a_hello_first_is_closed_without_an_answer(string first)
    {
        using var rig = new AgentRig();
        await using var pipe = await rig.RawClientAsync();
        await FrameIO.WriteAsync(pipe, Json(first), CancellationToken.None);
        using var cts = new CancellationTokenSource(5000);
        Assert.Null(await FrameIO.ReadAsync(pipe, cts.Token));
        Assert.Empty(rig.Fake.Requests);
    }

    [Fact]
    public async Task A_client_that_stays_silent_is_dropped_after_the_deadline()
    {
        using var rig = new AgentRig();
        await using var pipe = await rig.RawClientAsync();
        using var cts = new CancellationTokenSource(8000);
        var clock = Stopwatch.StartNew();
        Assert.Null(await FrameIO.ReadAsync(pipe, cts.Token));
        Assert.InRange(clock.Elapsed, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(6));
    }

    [Fact]
    public async Task An_oversize_frame_after_the_handshake_closes_the_connection()
    {
        using var rig = new AgentRig();
        await using var pipe = (await rig.ConnectAsync(CancellationToken.None))!;
        await pipe.WriteAsync(new byte[] { 0xff, 0xff, 0x01, 0x00 });
        await pipe.FlushAsync();
        using var cts = new CancellationTokenSource(5000);
        Assert.Null(await FrameIO.ReadAsync(pipe, cts.Token));
    }

    [Fact]
    public async Task Bad_messages_get_an_error_and_ten_in_a_row_close_the_connection()
    {
        using var rig = new AgentRig();
        await using var pipe = (await rig.ConnectAsync(CancellationToken.None))!;
        var first = await Ask(pipe, """{"v":1,"type":"nope","id":"a"}""");
        Assert.Equal(("error", "unknown_type"), (first.GetProperty("type").GetString(), first.GetProperty("error").GetString()));
        var hello = await Ask(pipe, """{"v":1,"type":"hello","secret":"not-the-real-secret-xx"}""");
        Assert.Equal("unknown_type", hello.GetProperty("error").GetString());
        for (var i = 0; i < 7; i++)
        {
            await Ask(pipe, "{}");
        }

        await FrameIO.WriteAsync(pipe, Json("{}"), CancellationToken.None);
        using var cts = new CancellationTokenSource(5000);
        await FrameIO.ReadAsync(pipe, cts.Token);
        Assert.Null(await FrameIO.ReadAsync(pipe, cts.Token));
        Assert.Empty(rig.Fake.Requests);
    }

    [Fact]
    public async Task A_url_check_returns_the_verdict_and_the_core_saw_the_browser_source()
    {
        var fake = new FakeCore { Respond = _ => FakeCore.Json("""{"verdict":{"state":"MALICIOUS","risk_score":91,"signals":[{"rule_id":"url.combosquat","description":"brand in a lookalike domain"}],"recommended_response":"BLOCK","explanation":"looks like a phishing page"},"persisted":false}""") };
        using var rig = new AgentRig(fake);
        await using var pipe = (await rig.ConnectAsync(CancellationToken.None))!;
        var answer = await Ask(pipe, """{"v":1,"type":"check_url","id":"c1","url":"https://paypal-login.test/login.php?token=SECRET"}""");
        Assert.Equal(("verdict", "c1", "MALICIOUS", 91), (answer.GetProperty("type").GetString(), answer.GetProperty("id").GetString(), answer.GetProperty("state").GetString(), answer.GetProperty("score").GetInt32()));
        Assert.Equal("brand in a lookalike domain", answer.GetProperty("reasons")[0].GetString());
        Assert.Equal("looks like a phishing page", answer.GetProperty("explanation").GetString());
        var seen = Assert.Single(fake.To("/v1/urls/analyze"));
        Assert.Contains("SECRET", Encoding.UTF8.GetString(seen.Body), StringComparison.Ordinal);
        Assert.Equal("Bearer t0k", seen.Auth);
    }

    [Theory]
    [InlineData(503, "core_unavailable")]
    [InlineData(401, "core_unavailable")]
    [InlineData(422, "rejected")]
    public async Task A_core_failure_is_reported_as_one_never_as_a_verdict(int code, string expected)
    {
        var fake = new FakeCore { Respond = _ => new HttpResponseMessage((HttpStatusCode)code) };
        using var rig = new AgentRig(fake);
        await using var pipe = (await rig.ConnectAsync(CancellationToken.None))!;
        var answer = await Ask(pipe, """{"v":1,"type":"check_url","id":"c1","url":"https://x.test/"}""");
        Assert.Equal(("error", expected), (answer.GetProperty("type").GetString(), answer.GetProperty("error").GetString()));
    }

    [Fact]
    public async Task An_override_is_recorded_through_the_core_and_returns_its_expiry()
    {
        var fake = new FakeCore { Respond = _ => FakeCore.Json("""{"recorded":true,"expires_at":"2026-11-05T12:15:00Z","stored_in":"database"}""") };
        using var rig = new AgentRig(fake);
        await using var pipe = (await rig.ConnectAsync(CancellationToken.None))!;
        var answer = await Ask(pipe, """{"v":1,"type":"override","id":"o1","url":"https://x.test/p","state":"MALICIOUS","minutes":15}""");
        Assert.Equal(("override_ok", "o1"), (answer.GetProperty("type").GetString(), answer.GetProperty("id").GetString()));
        using var sent = JsonDocument.Parse(Assert.Single(fake.To("/v1/overrides")).Body);
        Assert.Equal((15, "MALICIOUS"), (sent.RootElement.GetProperty("minutes").GetInt32(), sent.RootElement.GetProperty("state").GetString()));
    }

    [Theory]
    [InlineData(503)]
    [InlineData(422)]
    public async Task An_override_that_could_not_be_recorded_is_refused(int code)
    {
        var fake = new FakeCore { Respond = _ => new HttpResponseMessage((HttpStatusCode)code) };
        using var rig = new AgentRig(fake);
        await using var pipe = (await rig.ConnectAsync(CancellationToken.None))!;
        var answer = await Ask(pipe, """{"v":1,"type":"override","id":"o1","url":"https://x.test/p"}""");
        Assert.Equal("override_not_recorded", answer.GetProperty("error").GetString());
    }

    [Fact]
    public async Task More_than_the_allowed_number_of_clients_are_turned_away()
    {
        using var rig = new AgentRig();
        var open = new List<Stream>();
        for (var i = 0; i < PipeServer.MaxClients; i++)
        {
            open.Add((await rig.ConnectAsync(CancellationToken.None))!);
        }

        await using var extra = await rig.RawClientAsync();
        using var cts = new CancellationTokenSource(5000);
        Assert.Null(await FrameIO.ReadAsync(extra, cts.Token));
        foreach (var stream in open)
        {
            await stream.DisposeAsync();
        }
    }
}

public class BridgeTests
{
    private static async Task<(int Exit, List<JsonElement> Replies)> Drive(Bridge bridge, string origin, params string[] requests)
    {
        var input = new MemoryStream();
        foreach (var request in requests)
        {
            await FrameIO.WriteAsync(input, Encoding.UTF8.GetBytes(request), CancellationToken.None);
        }

        input.Position = 0;
        var output = new MemoryStream();
        var exit = await bridge.RunAsync(origin, input, output, CancellationToken.None);
        output.Position = 0;
        var replies = new List<JsonElement>();
        while (await FrameIO.ReadAsync(output, CancellationToken.None) is { } frame)
        {
            replies.Add(JsonDocument.Parse(frame).RootElement.Clone());
        }

        return (exit, replies);
    }

    private static Bridge To(AgentRig rig) => new([Endpoints.ExtensionOrigin], rig.ConnectAsync);

    [Fact]
    public async Task The_pinned_extension_gets_through_to_the_agent_and_the_host_ends_when_the_browser_does()
    {
        using var rig = new AgentRig();
        var (exit, replies) = await Drive(To(rig), Endpoints.ExtensionOrigin, """{"v":1,"type":"status","id":"a"}""", """{"v":1,"type":"status","id":"b"}""");
        Assert.Equal(0, exit);
        Assert.Equal(new[] { "a", "b" }, replies.Select(r => r.GetProperty("id").GetString()).ToArray());
        Assert.All(replies, r => Assert.Equal("status", r.GetProperty("type").GetString()));
    }

    [Theory]
    [InlineData("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/")]
    [InlineData("chrome-extension://ahnnfchmgkcemcljobhnmmgfdgcajhfo")]
    [InlineData("https://evil.test/")]
    [InlineData("")]
    public async Task Any_other_origin_is_refused_and_nothing_is_forwarded(string origin)
    {
        using var rig = new AgentRig();
        var (exit, replies) = await Drive(To(rig), origin, """{"v":1,"type":"check_url","id":"a","url":"https://x.test/"}""");
        Assert.Equal(3, exit);
        Assert.Equal("origin_refused", Assert.Single(replies).GetProperty("error").GetString());
        Assert.Empty(rig.Fake.Requests);
    }

    [Fact]
    public async Task A_missing_origin_argument_is_refused()
    {
        var bridge = new Bridge([Endpoints.ExtensionOrigin], _ => Task.FromResult<Stream?>(null));
        var exit = await bridge.RunAsync(null, new MemoryStream(), new MemoryStream(), CancellationToken.None);
        Assert.Equal(3, exit);
    }

    [Fact]
    public async Task Bad_and_unknown_messages_are_refused_at_the_host_and_never_reach_the_agent()
    {
        using var rig = new AgentRig();
        var (exit, replies) = await Drive(
            To(rig), Endpoints.ExtensionOrigin,
            "garbage", """{"v":1,"type":"hello","secret":"not-the-real-secret-xx"}""", """{"v":1,"type":"drop_tables","id":"a"}""",
            """{"v":1,"type":"check_url","id":"a"}""");
        Assert.Equal(0, exit);
        Assert.Equal(new[] { "malformed", "unknown_type", "unknown_type", "malformed" }, replies.Select(r => r.GetProperty("error").GetString()).ToArray());
        Assert.Empty(rig.Fake.Requests);
    }

    [Fact]
    public async Task With_no_agent_every_request_is_answered_at_once_and_the_host_keeps_running()
    {
        var attempts = 0;
        var bridge = new Bridge([Endpoints.ExtensionOrigin], _ =>
        {
            attempts++;
            return Task.FromResult<Stream?>(null);
        });
        var clock = Stopwatch.StartNew();
        var (exit, replies) = await Drive(bridge, Endpoints.ExtensionOrigin, """{"v":1,"type":"status","id":"a"}""", """{"v":1,"type":"status","id":"b"}""", """{"v":1,"type":"status","id":"c"}""");
        Assert.Equal(0, exit);
        Assert.Equal(3, replies.Count);
        Assert.All(replies, r => Assert.Equal("agent_unavailable", r.GetProperty("error").GetString()));
        Assert.Equal(new[] { "a", "b", "c" }, replies.Select(r => r.GetProperty("id").GetString()).ToArray());
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(1), "answered at once: " + clock.Elapsed);
        Assert.Equal(1, attempts); // the second and third did not try again inside the gap
    }

    [Fact]
    public async Task When_the_agent_restarts_the_host_reconnects_and_the_next_request_works()
    {
        var first = new AgentRig();
        var name = first.PipeName;
        var bridge = new Bridge([Endpoints.ExtensionOrigin], ct => Connector.ConnectAsync(name, AgentRig.Secret, ct));
        var output = new MemoryStream();
        var browser = new BlockingPair();
        var run = Task.Run(() => bridge.RunAsync(Endpoints.ExtensionOrigin, browser.Reader, output, CancellationToken.None));
        await browser.SendAsync("""{"v":1,"type":"status","id":"a"}""");
        await Wait.Until(() => Replies(output).Count >= 1, "the first reply");
        first.Dispose();

        await browser.SendAsync("""{"v":1,"type":"status","id":"b"}""");
        await Wait.Until(() => Replies(output).Count >= 2, "the reply while the agent is gone");
        await Task.Delay(Bridge.RetryGap + TimeSpan.FromMilliseconds(300));
        using var second = new AgentRig(pipeName: name);
        await browser.SendAsync("""{"v":1,"type":"status","id":"c"}""");
        await Wait.Until(() => Replies(output).Count >= 3, "the reply after the agent came back");
        browser.Complete();
        Assert.Equal(0, await run);
        var outcome = Replies(output).Select(r => r.TryGetProperty("error", out var e) ? e.GetString() : "ok").ToArray();
        Assert.Equal(new[] { "ok", "agent_unavailable", "ok" }, outcome);
    }

    [Fact]
    public async Task An_oversize_or_truncated_frame_from_the_browser_ends_the_host_cleanly()
    {
        var bridge = new Bridge([Endpoints.ExtensionOrigin], _ => Task.FromResult<Stream?>(null));
        var exit = await bridge.RunAsync(Endpoints.ExtensionOrigin, new MemoryStream([0xff, 0xff, 0xff, 0x7f]), new MemoryStream(), CancellationToken.None);
        Assert.Equal(4, exit);
        exit = await bridge.RunAsync(Endpoints.ExtensionOrigin, new MemoryStream([9, 0, 0, 0, 1]), new MemoryStream(), CancellationToken.None);
        Assert.Equal(4, exit);
    }

    [Fact]
    public async Task A_stuck_agent_costs_one_deadline_not_a_hang()
    {
        var (server, client) = Pair();
        var bridge = new Bridge([Endpoints.ExtensionOrigin], _ => Task.FromResult<Stream?>(client));
        var input = new MemoryStream();
        await FrameIO.WriteAsync(input, """{"v":1,"type":"status","id":"a"}"""u8.ToArray(), CancellationToken.None);
        input.Position = 0;
        var output = new MemoryStream();
        var clock = Stopwatch.StartNew();
        var exit = await bridge.RunAsync(Endpoints.ExtensionOrigin, input, output, CancellationToken.None);
        GC.KeepAlive(server);
        Assert.Equal(0, exit);
        Assert.InRange(clock.Elapsed, TimeSpan.FromSeconds(6), TimeSpan.FromSeconds(12));
        Assert.Equal("agent_timeout", Replies(output).Single().GetProperty("error").GetString());
    }

    private static (Stream Server, Stream Client) Pair()
    {
        var serverPipe = new AnonymousPipeServerStream(PipeDirection.In);
        var clientWrites = new AnonymousPipeClientStream(PipeDirection.Out, serverPipe.ClientSafePipeHandle);
        return (serverPipe, new DuplexSilent(serverPipe, clientWrites));
    }

    private static List<JsonElement> Replies(MemoryStream output)
    {
        var copy = new MemoryStream(output.ToArray());
        var replies = new List<JsonElement>();
        try
        {
            while (FrameIO.ReadAsync(copy, CancellationToken.None).GetAwaiter().GetResult() is { } frame)
            {
                replies.Add(JsonDocument.Parse(frame).RootElement.Clone());
            }
        }
        catch (FrameException)
        {
            // a frame still being written
        }

        return replies;
    }
}

/// <summary>An agent that accepts writes and never answers.</summary>
internal sealed class DuplexSilent(Stream read, Stream write) : Stream
{
    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override void Flush() => write.Flush();

    public override int Read(byte[] buffer, int offset, int count) => read.Read(buffer, offset, count);

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        await Task.Delay(Timeout.Infinite, cancellationToken);
        return 0;
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => write.Write(buffer, offset, count);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => write.WriteAsync(buffer, cancellationToken);
}

/// <summary>A stdin the test can feed one message at a time and then close.</summary>
internal sealed class BlockingPair
{
    private readonly AnonymousPipeServerStream writer = new(PipeDirection.Out);

    public BlockingPair() => Reader = new AnonymousPipeClientStream(PipeDirection.In, writer.ClientSafePipeHandle);

    public Stream Reader { get; }

    public Task SendAsync(string json) => FrameIO.WriteAsync(writer, Encoding.UTF8.GetBytes(json), CancellationToken.None);

    public void Complete() => writer.Dispose();
}

public class HostProcessTests
{
    [Fact]
    public async Task The_real_host_program_answers_at_once_with_no_agent_and_exits_when_stdin_closes()
    {
        var exe = Path.Combine(AppContext.BaseDirectory, "Mirage.NativeHost.exe");
        Assert.True(File.Exists(exe), "the host program was not built next to the tests");
        var start = new ProcessStartInfo(exe, Endpoints.ExtensionOrigin + " --parent-window=0")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        start.Environment["LOCALAPPDATA"] = Path.Combine(Path.GetTempPath(), "mirage-no-such-" + Guid.NewGuid().ToString("N"));
        using var process = Process.Start(start)!;
        var clock = Stopwatch.StartNew();
        await FrameIO.WriteAsync(process.StandardInput.BaseStream, """{"v":1,"type":"check_url","id":"z","url":"https://x.test/"}"""u8.ToArray(), CancellationToken.None);
        using var cts = new CancellationTokenSource(5000);
        var reply = JsonDocument.Parse((await FrameIO.ReadAsync(process.StandardOutput.BaseStream, cts.Token))!).RootElement;
        var answered = clock.Elapsed;
        process.StandardInput.Close();
        Assert.True(process.WaitForExit(5000), "the host did not exit when its input closed");
        Assert.Equal(("error", "agent_unavailable", "z", 0), (reply.GetProperty("type").GetString(), reply.GetProperty("error").GetString(), reply.GetProperty("id").GetString(), process.ExitCode));
        Assert.True(answered < TimeSpan.FromSeconds(2), "answered in " + answered);
    }

    [Fact]
    public async Task The_real_host_program_refuses_a_foreign_origin()
    {
        var exe = Path.Combine(AppContext.BaseDirectory, "Mirage.NativeHost.exe");
        var start = new ProcessStartInfo(exe, "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        using var process = Process.Start(start)!;
        using var cts = new CancellationTokenSource(5000);
        var reply = JsonDocument.Parse((await FrameIO.ReadAsync(process.StandardOutput.BaseStream, cts.Token))!).RootElement;
        Assert.True(process.WaitForExit(5000));
        Assert.Equal(("origin_refused", 3), (reply.GetProperty("error").GetString(), process.ExitCode));
    }
}
