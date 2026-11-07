using System.Globalization;
using System.IO.Pipes;
using Lynceus.Ipc;
using Lynceus.NativeHost;

namespace Lynceus.Agent.Tests;

/// <summary>Findings from the independent security review (R1): each one has a test that fails without its fix.</summary>
public sealed class HardeningTests
{
    [Fact]
    public void Every_format_character_is_removed_from_notification_text()
    {
        // all bidi embeddings/overrides/isolates and marks, zero-width characters, joiners, BOM, Arabic letter mark
        var hostile = "a\u202Ab\u202Bc\u202Cd\u202Ee\u200Ef\u200Fg\u2066h\u2067i\u2068j\u2069k\u200Bl\u200Dm\uFEFFn\u061Co";
        var cleaned = ToastText.Clean(hostile);
        Assert.Equal("a?b?c?d?e?f?g?h?i?j?k?l?m?n?o", cleaned);
        Assert.All(cleaned, c => Assert.NotEqual(UnicodeCategory.Format, CharUnicodeInfo.GetUnicodeCategory(c)));
        Assert.Equal("report.pdf", ToastText.Clean("report.pdf")); // ordinary text is untouched
    }

    private static AgentConfig Config(params string[] args) =>
        new() { CoreCommand = @"C:\python\python.exe", CoreWorkingDir = @"C:\mirage", CoreArgs = args.Length == 0 ? new AgentConfig().CoreArgs : args };

    [Fact]
    public void The_core_is_started_without_the_pythonpath_and_startup_hooks_the_agent_inherited()
    {
        var names = new[] { "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PYTHONUSERBASE", "pythonwarnings" };
        try
        {
            foreach (var name in names)
            {
                Environment.SetEnvironmentVariable(name, @"C:\attacker");
            }

            var info = new CoreSupervisor(Config(), "a-token-of-the-right-size", new ListLogger()).BuildStartInfo();
            Assert.DoesNotContain(info.Environment.Keys, k => k.StartsWith("PYTHON", StringComparison.OrdinalIgnoreCase) && !k.Equals("PYTHONNOUSERSITE", StringComparison.OrdinalIgnoreCase));
            Assert.Equal("1", info.Environment["PYTHONNOUSERSITE"]);
            Assert.Equal("a-token-of-the-right-size", info.Environment["LYNCEUS_API_TOKEN"]);
            Assert.DoesNotContain("a-token-of-the-right-size", string.Join(" ", info.ArgumentList)); // never on a command line
            Assert.Equal(@"C:\mirage", info.WorkingDirectory);
        }
        finally
        {
            foreach (var name in names)
            {
                Environment.SetEnvironmentVariable(name, null);
            }
        }
    }

    [Theory]
    [InlineData("--host", "0.0.0.0")]
    [InlineData("--host", "192.168.1.5")]
    [InlineData("--host", "::")]
    [InlineData("--host", "example.test")]
    [InlineData("--host=0.0.0.0", "")]
    public void A_core_that_would_listen_beyond_this_machine_is_refused(string first, string second)
    {
        var args = new[] { "-m", "uvicorn", "core.api.app:create_app", "--factory", first }.Concat(second.Length > 0 ? [second] : []).ToArray();
        var error = Assert.Throws<ConfigException>(() => Config(args).Validate());
        Assert.Contains("--host", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("--host", "127.0.0.1")]
    [InlineData("--host", "localhost")]
    [InlineData("--host=::1", "")]
    public void The_core_may_listen_on_this_machine(string first, string second)
    {
        var args = new[] { "-m", "uvicorn", "core.api.app:create_app", "--factory", first }.Concat(second.Length > 0 ? [second] : []).ToArray();
        Config(args).Validate();
        new AgentConfig().Validate(); // and the default is one of those
    }

    [Fact]
    public async Task A_program_holding_the_pipe_name_is_reported_and_the_server_takes_over_when_it_lets_go()
    {
        var name = "lynceus-test-" + Guid.NewGuid().ToString("N");
        var squatter = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        PipeServer.RetryEvery = TimeSpan.FromMilliseconds(50);
        using var stop = new CancellationTokenSource();
        try
        {
            var log = new ListLogger();
            var core = new CoreClient(new HttpClient(new FakeCore()) { BaseAddress = new Uri("http://127.0.0.1:8765") }, () => "t", verifyCore: false);
            var server = new PipeServer(name, AgentRig.Secret, new RequestHandler(core, () => new PipelineStats(0, 5, 0, 0, 0, 0, 0, 0, 2, 0)), log);
            var run = Task.Run(() => server.RunAsync(stop.Token));

            await Wait.Until(() => log.Messages.Any(m => m.Contains("taken by another program", StringComparison.Ordinal)), "the squatting to be reported");
            Assert.False(run.IsCompleted); // it did not give up

            await squatter.DisposeAsync();
            await using var pipe = await Connector.ConnectAsync(name, AgentRig.Secret, CancellationToken.None);
            Assert.NotNull(pipe); // protection came back by itself

            await stop.CancelAsync();
            await run;
        }
        finally
        {
            PipeServer.RetryEvery = TimeSpan.FromSeconds(5);
            await squatter.DisposeAsync();
        }
    }
}
