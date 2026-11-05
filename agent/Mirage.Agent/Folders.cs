using System.Runtime.InteropServices;

namespace Mirage.Agent;

/// <summary>The folders to watch: the configured ones, or the user's real Downloads folder.</summary>
public static partial class Folders
{
    private static readonly Guid Downloads = new("374DE290-123F-4565-9164-39C4925E467B");

    public static IReadOnlyList<string> ToWatch(AgentConfig config)
    {
        if (config.WatchFolders.Length > 0)
        {
            return config.WatchFolders;
        }

        return [DownloadsFolder()];
    }

    public static string DownloadsFolder()
    {
        var id = Downloads;
        if (SHGetKnownFolderPath(ref id, 0, IntPtr.Zero, out var pointer) == 0)
        {
            try
            {
                return Marshal.PtrToStringUni(pointer) ?? Fallback();
            }
            finally
            {
                Marshal.FreeCoTaskMem(pointer);
            }
        }

        return Fallback();
    }

    private static string Fallback() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

    [LibraryImport("shell32.dll")]
    private static partial int SHGetKnownFolderPath(ref Guid rfid, uint flags, IntPtr token, out IntPtr path);
}
