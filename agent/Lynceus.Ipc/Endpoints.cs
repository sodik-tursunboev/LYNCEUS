using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace Lynceus.Ipc;

/// <summary>Names and secrets shared by the agent and the native host. Nothing here is a credential for the core.</summary>
public static class Endpoints
{
    /// <summary>The one browser extension allowed to talk to the agent: its ID follows from the key pinned in the manifest.</summary>
    public const string ExtensionId = "ahnnfchmgkcemcljobhnmmgfdgcajhfo";

    public static string ExtensionOrigin => "chrome-extension://" + ExtensionId + "/";

    /// <summary>
    /// An environment variable by its LYNCEUS_ name, or by the MIRAGE_ name it had before the product was
    /// renamed (the new name wins), so an existing setup keeps working.
    /// </summary>
    public static string? Env(string name)
    {
        var value = Environment.GetEnvironmentVariable(name);
        if (!string.IsNullOrEmpty(value))
        {
            return value;
        }

        return name.StartsWith("LYNCEUS_", StringComparison.Ordinal)
            ? Environment.GetEnvironmentVariable("MIRAGE_" + name["LYNCEUS_".Length..])
            : null;
    }

    private static string LocalData => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    /// <summary>
    /// Where the agent keeps its files. LYNCEUS_AGENT_HOME moves it (used by the end-to-end tests so they never
    /// touch a real installation); otherwise it is %LOCALAPPDATA%\Lynceus. Until the folder the product used under
    /// its old name (%LOCALAPPDATA%\Mirage) has been moved there, that old folder is used, so nothing is lost if
    /// the move could not happen.
    /// </summary>
    public static string DataDir() =>
        Env("LYNCEUS_AGENT_HOME") is { Length: > 0 } home ? home : ChooseDataDir(LocalData);

    /// <summary>The default data folder under <paramref name="localAppData"/>: the new one, or the old one until it has been moved.</summary>
    public static string ChooseDataDir(string localAppData)
    {
        var current = Path.Combine(localAppData, "Lynceus");
        var legacy = Path.Combine(localAppData, "Mirage");
        return !Directory.Exists(current) && Directory.Exists(legacy) ? legacy : current;
    }

    /// <summary>
    /// Move the old data folder to the new name, once, on first start. Returns a note for the log, or null when
    /// there was nothing to do. A failed move (a file in use) is reported and the old folder stays in use.
    /// </summary>
    public static string? MigrateLegacyDataDir(string? localAppData = null)
    {
        if (localAppData is null && Env("LYNCEUS_AGENT_HOME") is { Length: > 0 })
        {
            return null;
        }

        var local = localAppData ?? LocalData;
        var current = Path.Combine(local, "Lynceus");
        var legacy = Path.Combine(local, "Mirage");
        if (Directory.Exists(current) || !Directory.Exists(legacy))
        {
            return null;
        }

        try
        {
            Directory.Move(legacy, current);
            return "moved the data folder from " + legacy + " to " + current;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return "could not move " + legacy + " to " + current + " (" + e.GetType().Name + "); the old folder stays in use";
        }
    }

    /// <summary>"" normally; a short tag of the data folder when it was moved, so a test agent and a real one cannot be confused.</summary>
    public static string InstanceTag() =>
        Env("LYNCEUS_AGENT_HOME") is { Length: > 0 } home
            ? "-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetFullPath(home).ToLowerInvariant())))[..8].ToLowerInvariant()
            : string.Empty;

    /// <summary>Per-user, so two users on one machine do not collide; the pipe itself is current-user only.</summary>
    public static string PipeName() => "lynceus-agent-" + WindowsIdentity.GetCurrent().User!.Value + InstanceTag();

    public static string SecretPath(string dataDir) => Path.Combine(dataDir, "pipe.secret");

    /// <summary>The per-install secret the host proves it knows. Created once, by the agent, and never overwritten.</summary>
    public static string LoadOrCreateSecret(string dataDir)
    {
        Directory.CreateDirectory(dataDir);
        var path = SecretPath(dataDir);
        if (!File.Exists(path))
        {
            var fresh = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            try
            {
                using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
                stream.Write(Encoding.ASCII.GetBytes(fresh));
            }
            catch (IOException) when (File.Exists(path))
            {
                // another start-up created it first: use theirs
            }
        }

        return ReadSecret(path) ?? throw new InvalidDataException("the pipe secret file is unreadable or too short");
    }

    /// <summary>The secret, or null if there is none yet or it is not usable.</summary>
    public static string? ReadSecret(string path)
    {
        try
        {
            var text = File.ReadAllText(path).Trim();
            return text.Length is >= 16 and <= 256 ? text : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
