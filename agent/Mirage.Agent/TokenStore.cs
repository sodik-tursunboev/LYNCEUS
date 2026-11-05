using System.Security.Cryptography;
using System.Text;

namespace Mirage.Agent;

/// <summary>
/// The API token the agent and the core share. It is kept in a file encrypted with DPAPI for the
/// current Windows user (no one else, and no other machine, can read it back). An explicit
/// MIRAGE_API_TOKEN in the environment wins, so a core someone else runs can be used.
/// </summary>
public static class TokenStore
{
    private static readonly byte[] Entropy = "mirage.agent.api-token.v1"u8.ToArray();

    public static string Path(string dataDir) => System.IO.Path.Combine(dataDir, "core.token");

    /// <summary>The token to use: the environment's, else the stored one (created on first use).</summary>
    public static string Resolve(string dataDir)
    {
        var fromEnv = Environment.GetEnvironmentVariable("MIRAGE_API_TOKEN");
        if (!string.IsNullOrWhiteSpace(fromEnv))
        {
            return fromEnv;
        }

        return Load(dataDir) ?? Save(dataDir, Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
    }

    public static string Save(string dataDir, string token)
    {
        Directory.CreateDirectory(dataDir);
        var protectedBytes = ProtectedData.Protect(Encoding.UTF8.GetBytes(token), Entropy, DataProtectionScope.CurrentUser);
        var temp = Path(dataDir) + ".tmp";
        File.WriteAllBytes(temp, protectedBytes);
        File.Move(temp, Path(dataDir), overwrite: true);
        return token;
    }

    public static string? Load(string dataDir)
    {
        try
        {
            var bytes = ProtectedData.Unprotect(File.ReadAllBytes(Path(dataDir)), Entropy, DataProtectionScope.CurrentUser);
            var token = Encoding.UTF8.GetString(bytes);
            return token.Length >= 16 ? token : null;
        }
        catch (Exception e) when (e is IOException or CryptographicException or UnauthorizedAccessException)
        {
            return null; // missing, from another user, or damaged: a new one is made
        }
    }
}
