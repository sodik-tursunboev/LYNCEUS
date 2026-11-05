using System.Text;
using System.Text.RegularExpressions;

namespace Mirage.Agent;

/// <summary>
/// The Mark of the Web a browser writes next to a download (the NTFS stream "Zone.Identifier").
/// It holds complete URLs, query string and fragment included, so this class returns the host
/// only. Nothing else leaves it: the URLs are not logged, queued or stored.
/// </summary>
public static partial class MarkOfTheWeb
{
    private const int MaxBytes = 16 * 1024;

    [GeneratedRegex("^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")]
    private static partial Regex HostPattern();

    /// <summary>The host the file came from, or null (no mark, not a web mark, unreadable).</summary>
    public static string? OriginHost(string path)
    {
        try
        {
            using var stream = new FileStream(
                path + ":Zone.Identifier", FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var buffer = new byte[MaxBytes];
            var read = stream.Read(buffer, 0, buffer.Length);
            return HostFrom(Encoding.UTF8.GetString(buffer, 0, read));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException)
        {
            return null;
        }
    }

    /// <summary>The whole mark as text (at most 16 KiB), or null. Used only to put it back after a restore: never logged or sent.</summary>
    public static string? RawStream(string path)
    {
        try
        {
            using var stream = new FileStream(
                path + ":Zone.Identifier", FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var buffer = new byte[MaxBytes];
            var read = stream.Read(buffer, 0, buffer.Length);
            return read == 0 ? null : Encoding.UTF8.GetString(buffer, 0, read);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException)
        {
            return null;
        }
    }

    /// <summary>HostUrl (where the file was fetched) first, then ReferrerUrl (the page that linked to it).</summary>
    public static string? HostFrom(string content)
    {
        string? hostUrl = null;
        string? referrer = null;
        foreach (var raw in content.Split('\n'))
        {
            var line = raw.Trim();
            var eq = line.IndexOf('=', StringComparison.Ordinal);
            if (eq <= 0)
            {
                continue;
            }

            var key = line[..eq].Trim();
            var value = line[(eq + 1)..].Trim();
            if (key.Equals("HostUrl", StringComparison.OrdinalIgnoreCase))
            {
                hostUrl ??= value;
            }
            else if (key.Equals("ReferrerUrl", StringComparison.OrdinalIgnoreCase))
            {
                referrer ??= value;
            }
        }

        return HostOf(hostUrl) ?? HostOf(referrer);
    }

    private static string? HostOf(string? url)
    {
        if (string.IsNullOrEmpty(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return null;
        }

        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
        {
            return null;
        }

        var host = uri.IdnHost.ToLowerInvariant().TrimEnd('.');
        return HostPattern().IsMatch(host) ? host : null;
    }
}
