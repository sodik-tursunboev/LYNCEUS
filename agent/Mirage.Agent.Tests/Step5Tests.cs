using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using Mirage.Ipc;

namespace Mirage.Agent.Tests;

public class TokenStoreTests
{
    [Fact]
    public void A_stored_token_round_trips_and_is_not_readable_in_the_file()
    {
        using var dir = new TestDir();
        var token = "tok-" + Guid.NewGuid().ToString("N");
        TokenStore.Save(dir.Path, token);
        Assert.Equal(token, TokenStore.Load(dir.Path));
        var raw = File.ReadAllBytes(TokenStore.Path(dir.Path));
        Assert.DoesNotContain(token, Encoding.UTF8.GetString(raw), StringComparison.Ordinal);
        Assert.DoesNotContain(token, Encoding.Unicode.GetString(raw), StringComparison.Ordinal);
    }

    [Fact]
    public void A_missing_or_damaged_file_gives_nothing_and_resolve_makes_a_new_token()
    {
        using var dir = new TestDir();
        Assert.Null(TokenStore.Load(dir.Path));
        File.WriteAllBytes(TokenStore.Path(dir.Path), [1, 2, 3, 4]);
        Assert.Null(TokenStore.Load(dir.Path));
        var made = TokenStore.Resolve(dir.Path);
        Assert.True(made.Length >= 32);
        Assert.Equal(made, TokenStore.Resolve(dir.Path));
    }

    [Fact]
    public void An_explicit_environment_token_wins()
    {
        using var dir = new TestDir();
        TokenStore.Save(dir.Path, "stored-token-0123456789");
        var before = Environment.GetEnvironmentVariable("MIRAGE_API_TOKEN");
        try
        {
            Environment.SetEnvironmentVariable("MIRAGE_API_TOKEN", "from-the-environment-0123");
            Assert.Equal("from-the-environment-0123", TokenStore.Resolve(dir.Path));
        }
        finally
        {
            Environment.SetEnvironmentVariable("MIRAGE_API_TOKEN", before);
        }
    }
}

public class ToastTests
{
    private static FileOutcome Outcome(string name, string state, params string[] reasons) =>
        new(new FileEvent("id", @"C:\Users\x\Downloads\" + name, name, 1, 1, DateTimeOffset.UtcNow), new string('a', 64), "origin.test", "pdf",
            new FileVerdict(state, 60, [], null, true, false, null, null, reasons));

    [Theory]
    [InlineData("MALICIOUS", "MIRAGE: dangerous file")]
    [InlineData("SUSPICIOUS", "MIRAGE: suspicious file")]
    public void A_bad_file_gets_a_notification_with_its_name_and_first_reason(string state, string title)
    {
        var text = ToastText.ForFile(Outcome("invoice.pdf.exe", state, "a double extension", "second"))!.Value;
        Assert.Equal(title, text.Title);
        Assert.Contains("invoice.pdf.exe", text.Body, StringComparison.Ordinal);
        Assert.Contains("a double extension", text.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("second", text.Body, StringComparison.Ordinal);
        Assert.Contains("Nothing was moved or deleted", text.Body, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("UNKNOWN")]
    [InlineData("ERROR")]
    [InlineData("BENIGN")]
    public void Anything_else_stays_quiet(string state) => Assert.Null(ToastText.ForFile(Outcome("a.txt", state)));

    [Fact]
    public void Hostile_names_are_made_safe_and_long_ones_cut()
    {
        var text = ToastText.ForFile(Outcome("evil\u202Efdp.exe\n\r" + new string('x', 300), "MALICIOUS"))!.Value;
        Assert.DoesNotContain('\u202E', text.Body);
        Assert.DoesNotContain('\r', text.Body.Split('\n')[0]);
        Assert.True(text.Body.Split('\n')[0].Length <= 80);
    }

    [Fact]
    public void A_block_names_the_host_only()
    {
        var text = ToastText.ForBlock("paypal-login.test", "MALICIOUS")!.Value;
        Assert.Equal("paypal-login.test", text.Body);
        Assert.Null(ToastText.ForBlock("x.test", "UNKNOWN"));
    }

    [Fact]
    public void The_toast_xml_escapes_markup()
    {
        var xml = WindowsToasts.Xml("a <b> & c", "\"quoted\" </text><text>injected");
        var document = new System.Xml.XmlDocument();
        document.LoadXml(xml);
        Assert.Equal(2, document.GetElementsByTagName("text").Count);
    }

    [Fact]
    public void A_real_toast_can_be_attempted_from_this_unpackaged_program()
    {
        var toasts = new WindowsToasts();
        toasts.Show("MIRAGE self-test", "A notification test from the agent's test run. Nothing is wrong.");
    }
}

public class InstallerTests
{
    [Fact]
    public void Install_registers_the_host_for_both_browsers_and_logon_and_uninstall_undoes_it()
    {
        using var dir = new TestDir();
        var host = Path.Combine(dir.Path, "Mirage.NativeHost.exe");
        File.WriteAllText(host, "stub");
        var root = @"Software\MirageTest-" + Guid.NewGuid().ToString("N");
        var installer = new Installer(dir.Path, @"C:\Program Files\Mirage\Mirage.Agent.exe", host, root);
        try
        {
            installer.Install();
            Assert.Equal((true, true, true, true), installer.Status());
            using var run = Registry.CurrentUser.OpenSubKey(root + @"\Microsoft\Windows\CurrentVersion\Run")!;
            Assert.Equal("\"C:\\Program Files\\Mirage\\Mirage.Agent.exe\"", run.GetValue("MirageAgent"));

            using var manifest = JsonDocument.Parse(File.ReadAllText(installer.ManifestPath));
            var m = manifest.RootElement;
            Assert.Equal(("com.mirage.agent", "stdio", host), (m.GetProperty("name").GetString(), m.GetProperty("type").GetString(), m.GetProperty("path").GetString()));
            Assert.Equal(Endpoints.ExtensionOrigin, Assert.Single(m.GetProperty("allowed_origins").EnumerateArray()).GetString());

            installer.Install(); // twice is fine
            installer.Uninstall();
            Assert.Equal((false, false, false, false), installer.Status());
            installer.Uninstall(); // and so is undoing twice
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(root, throwOnMissingSubKey: false);
        }
    }

    [Fact]
    public void Install_refuses_when_the_host_program_is_missing()
    {
        using var dir = new TestDir();
        var root = @"Software\MirageTest-" + Guid.NewGuid().ToString("N");
        try
        {
            Assert.Throws<FileNotFoundException>(() => new Installer(dir.Path, "a.exe", Path.Combine(dir.Path, "nope.exe"), root).Install());
            Assert.Null(Registry.CurrentUser.OpenSubKey(root));
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(root, throwOnMissingSubKey: false);
        }
    }

    [Fact]
    public void The_manifest_allows_exactly_the_pinned_extension_and_no_wildcard()
    {
        var text = Installer.ManifestJson(@"C:\x\host.exe");
        Assert.DoesNotContain('*', text);
        Assert.Contains("chrome-extension://ahnnfchmgkcemcljobhnmmgfdgcajhfo/", text, StringComparison.Ordinal);
    }
}

public class RequestHandlerAnnounceTests
{
    private static async Task<(string Reply, List<(string Host, string State)> Seen)> Run(string state, bool callbackThrows)
    {
        var fake = new FakeCore { Respond = _ => FakeCore.Json(FakeCore.Verdict(state)) };
        var seen = new List<(string, string)>();
        var handler = new RequestHandler(
            new CoreClient(new HttpClient(fake) { BaseAddress = new Uri("http://127.0.0.1:8765") }, () => "t", verifyCore: false),
            () => new PipelineStats(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            (host, st) =>
            {
                seen.Add((host, st));
                if (callbackThrows)
                {
                    throw new InvalidOperationException("toast failed");
                }
            });
        Assert.True(Protocol.TryParse("""{"v":1,"type":"check_url","id":"a","url":"https://Paypal-Login.test/p?token=SECRET"}"""u8, out var request, out _));
        return (Encoding.UTF8.GetString(await handler.HandleAsync(request!, CancellationToken.None)), seen);
    }

    [Theory]
    [InlineData("MALICIOUS")]
    [InlineData("SUSPICIOUS")]
    public async Task A_bad_page_is_announced_with_its_host_only(string state)
    {
        var (_, seen) = await Run(state, false);
        Assert.Equal([("paypal-login.test", state)], seen);
    }

    [Theory]
    [InlineData("UNKNOWN")]
    [InlineData("BENIGN")]
    [InlineData("ERROR")]
    public async Task Other_verdicts_are_not_announced(string state) => Assert.Empty((await Run(state, false)).Seen);

    [Fact]
    public async Task A_notification_failure_never_costs_the_reply()
    {
        var (reply, seen) = await Run("MALICIOUS", true);
        Assert.Single(seen);
        Assert.Contains("\"state\":\"MALICIOUS\"", reply, StringComparison.Ordinal);
    }
}

public class ConfigCoreTests
{
    [Theory]
    [InlineData("""{"CoreCommand":"python.exe","CoreWorkingDir":"C:\\mirage"}""")]
    [InlineData("""{"CoreCommand":"C:\\py\\python.exe"}""")]
    [InlineData("""{"CoreCommand":"C:\\py\\python.exe","CoreWorkingDir":"relative"}""")]
    [InlineData("""{"CoreIntelDeadlineSeconds":0}""")]
    [InlineData("""{"CoreIntelDeadlineSeconds":99}""")]
    public void An_unusable_core_setup_is_refused(string json)
    {
        using var dir = new TestDir();
        var path = Path.Combine(dir.Path, "agent.json");
        File.WriteAllText(path, json);
        Assert.Throws<ConfigException>(() => AgentConfig.Load(path));
    }

    [Fact]
    public void A_full_path_setup_is_accepted()
    {
        using var dir = new TestDir();
        var path = Path.Combine(dir.Path, "agent.json");
        File.WriteAllText(path, """{"CoreCommand":"C:\\mirage\\.venv\\Scripts\\python.exe","CoreWorkingDir":"C:\\mirage"}""");
        Assert.Equal("C:\\mirage", AgentConfig.Load(path).CoreWorkingDir);
    }
}

public class CoreSupervisorTests
{
    private const string Stub = """
        import http.server, json, os, sys
        port, out = int(sys.argv[1]), sys.argv[2]
        open(out, "w").write(json.dumps({"token": os.environ.get("MIRAGE_API_TOKEN"), "deadline": os.environ.get("MIRAGE_INTEL_DEADLINE"), "pid": os.getpid(), "argv": sys.argv[1:]}))
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
            def log_message(self, *a): pass
        http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
        """;

    private static string Python()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "CLAUDE.md")))
            {
                var py = Path.Combine(dir.FullName, ".venv", "Scripts", "python.exe");
                Assert.True(File.Exists(py), "the project's Python is needed for this test: " + py);
                return py;
            }
        }

        throw new Xunit.Sdk.XunitException("project folder not found");
    }

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    private static (AgentConfig Config, string Out) Setup(TestDir dir, int port, string? script = null)
    {
        var file = Path.Combine(dir.Path, "stub.py");
        File.WriteAllText(file, script ?? Stub);
        var output = Path.Combine(dir.Path, "out.json");
        return (new AgentConfig { CoreUrl = $"http://127.0.0.1:{port}", CoreCommand = Python(), CoreWorkingDir = dir.Path, CoreArgs = [file, port.ToString(System.Globalization.CultureInfo.InvariantCulture), output], CoreIntelDeadlineSeconds = 0.5 }, output);
    }

    private static async Task<bool> Answers(int port)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(1) };
        try
        {
            return (await http.GetAsync($"http://127.0.0.1:{port}/health")).IsSuccessStatusCode;
        }
        catch (HttpRequestException)
        {
            return false;
        }
        catch (TaskCanceledException)
        {
            return false;
        }
    }

    [Fact]
    public async Task It_starts_the_core_with_the_token_in_the_environment_and_stops_it_when_asked()
    {
        using var dir = new TestDir();
        var port = FreePort();
        var (config, output) = Setup(dir, port);
        var supervisor = new CoreSupervisor(config, "secret-token-for-the-child", new ListLogger());
        using var stop = new CancellationTokenSource();
        var run = Task.Run(() => supervisor.RunAsync(stop.Token));
        await Wait.Until(() => File.Exists(output) && new FileInfo(output).Length > 0, "the child to start");
        await Wait.Until(() => Answers(port).GetAwaiter().GetResult(), "the child to answer");

        using var seen = JsonDocument.Parse(File.ReadAllText(output));
        Assert.Equal(("secret-token-for-the-child", "0.5"), (seen.RootElement.GetProperty("token").GetString(), seen.RootElement.GetProperty("deadline").GetString()));
        Assert.DoesNotContain("secret-token", string.Join(' ', seen.RootElement.GetProperty("argv").EnumerateArray().Select(a => a.GetString())), StringComparison.Ordinal);

        await stop.CancelAsync();
        await run;
        await Wait.Until(() => !Answers(port).GetAwaiter().GetResult(), "the child to be gone");
    }

    [Fact]
    public async Task It_starts_the_core_again_after_it_is_killed()
    {
        using var dir = new TestDir();
        var port = FreePort();
        var (config, output) = Setup(dir, port);
        var supervisor = new CoreSupervisor(config, "secret-token-for-the-child", new ListLogger());
        using var stop = new CancellationTokenSource();
        var run = Task.Run(() => supervisor.RunAsync(stop.Token));
        await Wait.Until(() => Answers(port).GetAwaiter().GetResult(), "the first start");
        var pid = JsonDocument.Parse(File.ReadAllText(output)).RootElement.GetProperty("pid").GetInt32();
        Process.GetProcessById(pid).Kill();
        await Wait.Until(() => supervisor.Starts >= 2, "a second start", 30_000);
        await Wait.Until(() => Answers(port).GetAwaiter().GetResult(), "the second child to answer");
        await stop.CancelAsync();
        await run;
    }

    [Fact]
    public async Task It_leaves_a_core_that_someone_else_runs_alone()
    {
        using var dir = new TestDir();
        var port = FreePort();
        var (config, _) = Setup(dir, port);
        var other = Process.Start(new ProcessStartInfo(config.CoreCommand!, config.CoreArgs.Select(a => $"\"{a}\"").Aggregate((a, b) => a + " " + b)) { UseShellExecute = false, CreateNoWindow = true })!;
        try
        {
            await Wait.Until(() => Answers(port).GetAwaiter().GetResult(), "the other core");
            var supervisor = new CoreSupervisor(config, "t", new ListLogger());
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            await supervisor.RunAsync(stop.Token);
            Assert.Equal(0, supervisor.Starts);
            Assert.False(other.HasExited);
        }
        finally
        {
            other.Kill(entireProcessTree: true);
        }
    }

    [Fact]
    public async Task A_core_that_dies_at_once_is_not_restarted_in_a_tight_loop()
    {
        using var dir = new TestDir();
        var port = FreePort();
        var (config, _) = Setup(dir, port, "import sys\nsys.exit(3)\n");
        var supervisor = new CoreSupervisor(config, "t", new ListLogger());
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(6));
        await supervisor.RunAsync(stop.Token);
        Assert.InRange(supervisor.Starts, 1, 4);
    }

    [Fact]
    public async Task With_no_core_command_it_does_nothing()
    {
        var supervisor = new CoreSupervisor(new AgentConfig(), "t", new ListLogger());
        await supervisor.RunAsync(CancellationToken.None);
        Assert.Equal(0, supervisor.Starts);
    }
}
