using System.Runtime.InteropServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Mirage.Agent;

const string Usage = "MIRAGE agent. Without arguments it runs in the background.\n  --install     start at logon and register the browser bridge for Edge and Chrome\n  --uninstall   undo --install\n  --status      show what is registered\n  --set-token   read the core's API token from standard input and store it (DPAPI)";

[DllImport("kernel32.dll")]
static extern bool AttachConsole(int processId);

if (args.Length > 0)
{
    AttachConsole(-1); // a windowless program still answers in the terminal it was started from
    Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
    Console.SetError(new StreamWriter(Console.OpenStandardError()) { AutoFlush = true });
}

AgentConfig config;
try
{
    config = AgentConfig.Load(Path.Combine(AgentConfig.DefaultDataDir, "agent.json"));
}
catch (ConfigException e)
{
    Console.Error.WriteLine("MIRAGE agent: " + e.Message);
    new RollingLog(Path.Combine(AgentConfig.DefaultDataDir, "agent.log")).WriteLine("configuration refused: " + e.Message);
    return 2;
}

var installer = new Installer(
    config.ResolvedDataDir,
    Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "Mirage.Agent.exe"),
    Path.Combine(AppContext.BaseDirectory, "Mirage.NativeHost.exe"));
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

using var single = new Mutex(initiallyOwned: true, @"Local\Mirage.Agent", out var first);
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
