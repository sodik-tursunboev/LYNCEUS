namespace Lynceus.Agent.Tests;

public class ConsoleLinkTests
{
    private const string Code = "Abc_def-0123456789xyz";

    [Fact]
    public void The_link_points_at_the_local_console_and_carries_the_code_only_after_the_hash()
    {
        var link = ConsoleLink.Build("http://127.0.0.1:8765", Code);
        Assert.Equal("http://127.0.0.1:8765/console/#code=" + Code, link);
        Assert.DoesNotContain("Abc", link[..link.IndexOf('#', StringComparison.Ordinal)], StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("http://example.com")]
    [InlineData("https://127.0.0.1")]
    [InlineData("http://10.0.0.1:8765")]
    public void It_refuses_an_address_that_is_not_this_machine(string url) =>
        Assert.Throws<ArgumentException>(() => ConsoleLink.Build(url, "x"));

    [Fact]
    public async Task The_code_comes_from_the_core_and_the_token_never_enters_the_link()
    {
        var fake = new FakeCore { Respond = s => s.Path == "/v1/console/code" ? FakeCore.Json($$"""{"code":"{{Code}}","expires_in":60}""") : FakeCore.Json("{}") };
        var client = new CoreClient(new HttpClient(fake) { BaseAddress = new Uri("http://127.0.0.1:8765") }, () => "the-api-token-1234", verifyCore: false);
        var (status, code) = await client.ConsoleCodeAsync(CancellationToken.None);
        Assert.Equal((CoreStatus.Ok, Code), (status, code));
        Assert.Equal("Bearer the-api-token-1234", fake.Requests.Single(r => r.Path == "/v1/console/code").Auth);
        Assert.DoesNotContain("the-api-token", ConsoleLink.Build("http://127.0.0.1:8765", code!), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("""{"code":"short"}""")]
    [InlineData("""{"code":"has spaces in it 0123456789"}""")]
    [InlineData("""{"code":"<script>alert(1)</script>xxxx"}""")]
    [InlineData("""{"nothing":true}""")]
    [InlineData("not json")]
    public async Task A_strange_answer_gives_no_code(string body)
    {
        var fake = new FakeCore { Respond = _ => FakeCore.Json(body) };
        var client = new CoreClient(new HttpClient(fake) { BaseAddress = new Uri("http://127.0.0.1:8765") }, () => "t", verifyCore: false);
        var (_, code) = await client.ConsoleCodeAsync(CancellationToken.None);
        Assert.Null(code);
    }
}
