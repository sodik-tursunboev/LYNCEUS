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

    /// <summary>Per-user, so two users on one machine do not collide; the pipe itself is current-user only.</summary>
    public static string PipeName() => "mirage-agent-" + WindowsIdentity.GetCurrent().User!.Value;

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
