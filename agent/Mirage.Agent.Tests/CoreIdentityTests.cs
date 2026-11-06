using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Mirage.Agent.Tests;

/// <summary>
/// Any local program can listen on the core's port. The agent must see proof that it is talking to the core
/// (an HMAC of a fresh nonce keyed by the API token) before the token, a URL or a file leaves the machine's
/// own process. These tests use a scripted program on the port, with the handshake switched on.
/// </summary>
public sealed class CoreIdentityTests
{
    private const string Token = "a-long-enough-token-for-the-handshake";

    private static string Proof(string token, string nonce) =>
        Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(token), Encoding.ASCII.GetBytes(nonce))).ToLowerInvariant();

    private static string NonceOf(Seen s) => s.Query.Split("nonce=")[1].Split('&')[0];

    private static (CoreClient Client, FakeCore Fake) Make(Func<Seen, HttpResponseMessage> respond)
    {
        var fake = new FakeCore { Respond = respond };
        return (new CoreClient(new HttpClient(fake) { BaseAddress = new Uri("http://127.0.0.1:8765") }, () => Token), fake);
    }

    private static HttpResponseMessage RealCore(Seen s) =>
        s.Path == "/health"
            ? FakeCore.Json($$"""{"status":"ok","proof":"{{Proof(Token, NonceOf(s))}}"}""")
            : FakeCore.Json(FakeCore.Suspicious);

    private static int Health(FakeCore fake) => fake.Requests.Count(r => r.Path == "/health");

    [Fact]
    public async Task The_real_core_is_trusted_and_only_then_receives_the_token()
    {
        var (client, fake) = Make(RealCore);
        var result = await client.CheckUrlAsync("https://paypal-login.test/x", CancellationToken.None);
        Assert.Equal(CoreStatus.Ok, result.Status);
        Assert.Null(fake.Requests.Single(r => r.Path == "/health").Auth); // the question carries no secret
        Assert.Equal("Bearer " + Token, fake.Requests.Single(r => r.Path == "/v1/urls/analyze").Auth);
        Assert.Equal(32, NonceOf(fake.Requests.First()).Length); // a fresh random nonce
    }

    [Fact]
    public async Task The_proof_is_reused_for_a_short_time_and_not_asked_for_on_every_request()
    {
        var (client, fake) = Make(RealCore);
        for (var i = 0; i < 5; i++)
        {
            Assert.Equal(CoreStatus.Ok, (await client.CheckUrlAsync("https://x.test/" + i, CancellationToken.None)).Status);
        }

        Assert.Equal(1, Health(fake));
        Assert.Equal(5, fake.Requests.Count(r => r.Path == "/v1/urls/analyze"));
    }

    [Fact]
    public async Task A_failure_makes_the_agent_prove_the_core_again_before_the_next_secret_goes_out()
    {
        var down = false;
        var (client, fake) = Make(s => down && s.Path != "/health" ? new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) : RealCore(s));
        await client.CheckUrlAsync("https://x.test/1", CancellationToken.None);
        down = true;
        Assert.Equal(CoreStatus.Unavailable, (await client.CheckUrlAsync("https://x.test/2", CancellationToken.None)).Status);
        down = false;
        await client.CheckUrlAsync("https://x.test/3", CancellationToken.None);
        Assert.Equal(2, Health(fake)); // once at the start, once again after the failure
    }

    public static TheoryData<string, Func<Seen, HttpResponseMessage>> Impostors() => new()
    {
        { "answers 200 to everything, knows no proof", s => FakeCore.Json(s.Path == "/health" ? """{"status":"ok"}""" : FakeCore.Verdict("BENIGN")) },
        { "a proof made with another key", s => FakeCore.Json($$"""{"status":"ok","proof":"{{Proof("some-other-token-entirely", s.Path == "/health" ? NonceOf(s) : "")}}"}""") },
        { "a proof for a different nonce (a replay)", s => FakeCore.Json($$"""{"status":"ok","proof":"{{Proof(Token, "00000000000000000000000000000000")}}"}""") },
        { "a proof that is not hex", s => FakeCore.Json("""{"status":"ok","proof":"not hex at all"}""") },
        { "a proof that is not a string", s => FakeCore.Json("""{"status":"ok","proof":123}""") },
        { "health is not JSON", s => FakeCore.Json("<html>hello</html>") },
        { "health is a JSON array", s => FakeCore.Json("[]") },
        { "health refuses", s => new HttpResponseMessage(HttpStatusCode.Forbidden) },
        { "health redirects away", s => new HttpResponseMessage(HttpStatusCode.Redirect) },
    };

    [Theory]
    [MemberData(nameof(Impostors))]
    public async Task A_program_that_cannot_prove_it_is_the_core_never_gets_the_token_the_url_or_a_file(string name, Func<Seen, HttpResponseMessage> respond)
    {
        var (client, fake) = Make(respond);
        var url = await client.CheckUrlAsync("https://private-bank.test/login?session=SECRET", CancellationToken.None);
        var file = await client.AnalyzeAsync("tax-return.pdf", new string('a', 64), "x.test", new byte[] { 1, 2, 3 }, CancellationToken.None);
        var check = await client.CheckAsync("a.exe", 3, new string('b', 64), null, null, CancellationToken.None);
        var actions = await client.ListActionsAsync("PENDING", CancellationToken.None);
        var approve = await client.ApproveAsync(Guid.NewGuid(), CancellationToken.None);

        Assert.True(url.Status == CoreStatus.Unavailable && url.Detail == "core_identity", name);
        Assert.Equal(CoreStatus.Unavailable, file.Status);
        Assert.Equal(CoreStatus.Unavailable, check.Status);
        Assert.Equal(CoreStatus.Unavailable, actions.Status);
        Assert.Equal(CoreStatus.Unavailable, approve);
        Assert.All(fake.Requests, r =>
        {
            Assert.Equal("/health", r.Path); // the only thing ever sent
            Assert.Null(r.Auth);
            Assert.Empty(r.Body);
        });
        Assert.DoesNotContain(fake.Requests, r => r.Query.Contains("SECRET", StringComparison.Ordinal));
    }
}
