namespace Mirage.Agent.Tests;

public class ConsoleLinkTests
{
    [Fact]
    public void The_link_points_at_the_local_console_and_carries_the_token_only_after_the_hash()
    {
        var link = ConsoleLink.Build("http://127.0.0.1:8765", "abc+def/ghi=0123456789");
        Assert.Equal("http://127.0.0.1:8765/console/#token=abc+def/ghi=0123456789", link);
        Assert.DoesNotContain("abc", link[..link.IndexOf('#', StringComparison.Ordinal)], StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("http://example.com")]
    [InlineData("https://127.0.0.1")]
    [InlineData("http://10.0.0.1:8765")]
    public void It_refuses_an_address_that_is_not_this_machine(string url) =>
        Assert.Throws<ArgumentException>(() => ConsoleLink.Build(url, "x"));
}
