using System.Runtime.InteropServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Lynceus.Agent;

const string Usage = "Lynceus agent. Without arguments it runs in the background.\n  --install     start at logon and register the browser bridge for Edge and Chrome\n  --uninstall   undo --install\n  --status      show what is registered\n  --set-token   read the core's API token from standard input and store it (DPAPI)\n  --open-console open the Lynceus console in your browser, already signed in\n  --console-link print the signed-in console address (used by the native console window)";

[DllImport("kernel32.dll")]
static extern bool AttachConsole(int processId);

if (args.Length > 0)
{
    AttachConsole(-1); // a windowless program still answers in the terminal it was started from
    Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
    Console.SetError(new StreamWriter(Console.OpenStandardError()) { AutoFlush = true });
}

// The product used to be called MIRAGE: move its data folder to the new name once, before anything reads it.
if (Lynceus.Ipc.Endpoints.MigrateLegacyDataDir() is { } moved)
{
    new RollingLog(Path.Combine(AgentConfig.DefaultDataDir, "agent.log")).WriteLine(moved);
}

AgentConfig config;
try
{
    config = AgentConfig.Load(Path.Combine(AgentConfig.DefaultDataDir, "agent.json"));
}
catch (ConfigException e)
{
    Console.Error.WriteLine("Lynceus agent: " + e.Message);
    new RollingLog(Path.Combine(AgentConfig.DefaultDataDir, "agent.log")).WriteLine("configuration refused: " + e.Message);
    return 2;
}

var installer = new Installer(
    config.ResolvedDataDir,
    Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "Lynceus.Agent.exe"),
    Path.Combine(AppContext.BaseDirectory, "Lynceus.NativeHost.exe"));
switch (args.FirstOrDefault())
{
    case "--install":
        installer.Install();
        Console.WriteLine("Installed: starts at logon; browser bridge registered for Edge and Chrome. Load the extension from extension\\dist in the browser.");
        return 0;
    case "--uninstall":
        installer.Uninstall();
        Console.WriteLine("Uninstalled.");
        return 0;
    case "--status":
        var s = installer.Status();
        Console.WriteLine($"at logon: {s.AtLogon}; Edge bridge: {s.Edge}; Chrome bridge: {s.Chrome}; host manifest: {s.Manifest}");
        return 0;
    case "--open-console":
    case "--console-link":
        // the link carries a one-time code from the core, never the token (H1 A1)
        var (link, problem) = await ConsoleLink.FetchAsync(config.CoreUrl, TokenStore.Resolve(config.ResolvedDataDir), CancellationToken.None);
        if (link is null)
        {
            Console.Error.WriteLine(problem);
            return 1;
        }

        if (args[0] == "--console-link")
        {
            Console.WriteLine(link); // for the native console window: nothing opened
            return 0;
        }

        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(link) { UseShellExecute = true });
        Console.WriteLine("Opened the console in your browser.");
        return 0;
    case "--set-token":
        var token = (Console.In.ReadLine() ?? string.Empty).Trim();
        if (token.Length < 16)
        {
            Console.Error.WriteLine("The token must be at least 16 characters, given on standard input.");
            return 2;
        }

        TokenStore.Save(config.ResolvedDataDir, token);
        Console.WriteLine("Token stored.");
        return 0;
    case null:
        break;
    default:
        Console.WriteLine(Usage);
        return 2;
}

using var single = new Mutex(initiallyOwned: true, @"Local\Lynceus.Agent" + Lynceus.Ipc.Endpoints.InstanceTag(), out var first);
if (!first)
{
    return 0; // already running for this user
}

var builder = Host.CreateApplicationBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddProvider(new FileLoggerProvider(new RollingLog(Path.Combine(config.ResolvedDataDir, "agent.log"))));
builder.Services.AddSingleton(config);
builder.Services.AddHostedService<AgentService>();
await builder.Build().RunAsync();
return 0;
