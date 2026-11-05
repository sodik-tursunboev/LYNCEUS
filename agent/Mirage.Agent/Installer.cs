using System.Text.Json;
using Microsoft.Win32;
using Mirage.Ipc;

namespace Mirage.Agent;

/// <summary>
/// Per-user set-up, no administrator needed: start the agent at logon (the current user's Run
/// key) and tell Edge and Chrome where the native messaging host is. The browser extension
/// itself is added by the user (Load unpacked) until the M7 installer.
/// </summary>
public sealed class Installer(string dataDir, string agentExe, string hostExe, string registryRoot = "Software")
{
    public const string HostName = "com.mirage.agent";
    public const string RunValue = "MirageAgent";
    private static readonly JsonSerializerOptions Pretty = new() { WriteIndented = true };
    private static readonly string[] BrowserKeys = [@"Microsoft\Edge\NativeMessagingHosts", @"Google\Chrome\NativeMessagingHosts"];

    public string ManifestPath => Path.Combine(dataDir, "native-host", HostName + ".json");

    public void Install()
    {
        if (!File.Exists(hostExe))
        {
            throw new FileNotFoundException("the native host program is missing", hostExe);
        }

        Directory.CreateDirectory(Path.GetDirectoryName(ManifestPath)!);
        File.WriteAllText(ManifestPath, ManifestJson(hostExe));
        foreach (var browser in BrowserKeys)
        {
            using var key = Registry.CurrentUser.CreateSubKey($@"{registryRoot}\{browser}\{HostName}");
            key.SetValue(string.Empty, ManifestPath);
        }

        using var run = Registry.CurrentUser.CreateSubKey($@"{registryRoot}\Microsoft\Windows\CurrentVersion\Run");
        run.SetValue(RunValue, $"\"{agentExe}\"");
    }

    public void Uninstall()
    {
        foreach (var browser in BrowserKeys)
        {
            Registry.CurrentUser.DeleteSubKeyTree($@"{registryRoot}\{browser}\{HostName}", throwOnMissingSubKey: false);
        }

        using var run = Registry.CurrentUser.OpenSubKey($@"{registryRoot}\Microsoft\Windows\CurrentVersion\Run", writable: true);
        run?.DeleteValue(RunValue, throwOnMissingValue: false);
        if (File.Exists(ManifestPath))
        {
            File.Delete(ManifestPath);
        }
    }

    /// <summary>What is registered right now, for `--status`.</summary>
    public (bool AtLogon, bool Edge, bool Chrome, bool Manifest) Status()
    {
        using var run = Registry.CurrentUser.OpenSubKey($@"{registryRoot}\Microsoft\Windows\CurrentVersion\Run");
        bool Has(string browser)
        {
            using var key = Registry.CurrentUser.OpenSubKey($@"{registryRoot}\{browser}\{HostName}");
            return key?.GetValue(string.Empty) as string == ManifestPath;
        }

        return (run?.GetValue(RunValue) is string, Has(BrowserKeys[0]), Has(BrowserKeys[1]), File.Exists(ManifestPath));
    }

    /// <summary>The host manifest: one program, one allowed extension, no wildcards.</summary>
    public static string ManifestJson(string hostPath) => JsonSerializer.Serialize(
        new Dictionary<string, object>
        {
            ["name"] = HostName,
            ["description"] = "MIRAGE agent bridge",
            ["path"] = hostPath,
            ["type"] = "stdio",
            ["allowed_origins"] = new[] { Endpoints.ExtensionOrigin },
        },
        Pretty);
}
