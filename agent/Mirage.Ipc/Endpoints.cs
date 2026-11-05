using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace Mirage.Ipc;

/// <summary>Names and secrets shared by the agent and the native host. Nothing here is a credential for the core.</summary>
public static class Endpoints
{
    /// <summary>The one browser extension allowed to talk to the agent: its ID follows from the key pinned in the manifest.</summary>
    public const string ExtensionId = "ahnnfchmgkcemcljobhnmmgfdgcajhfo";

    public static string ExtensionOrigin => "chrome-extension://" + ExtensionId + "/";

    /// <summary>
    /// Where the agent keeps its files. MIRAGE_AGENT_HOME moves it (used by the end-to-end tests so they never
    /// touch a real installation); otherwise it is %LOCALAPPDATA%\Mirage.
    /// </summary>
    public static string DataDir() =>
        Environment.GetEnvironmentVariable("MIRAGE_AGENT_HOME") is { Length: > 0 } home
            ? home
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Mirage");

    /// <summary>"" normally; a short tag of the data folder when it was moved, so a test agent and a real one cannot be confused.</summary>
    public static string InstanceTag() =>
        Environment.GetEnvironmentVariable("MIRAGE_AGENT_HOME") is { Length: > 0 } home
            ? "-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetFullPath(home).ToLowerInvariant())))[..8].ToLowerInvariant()
            : string.Empty;

    /// <summary>Per-user, so two users on one machine do not collide; the pipe itself is current-user only.</summary>
    public static string PipeName() => "mirage-agent-" + WindowsIdentity.GetCurrent().User!.Value + InstanceTag();

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
