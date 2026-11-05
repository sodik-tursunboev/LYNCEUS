namespace Mirage.Agent;

/// <summary>
/// The address that opens the console already signed in. The token travels in the address fragment, which the
/// browser never sends to any server; the console reads it once and removes it from the address bar.
/// </summary>
public static class ConsoleLink
{
    public static string Build(string coreUrl, string token)
    {
        var uri = new Uri(coreUrl);
        if (!CoreHttp.IsLoopbackUrl(uri))
        {
            throw new ArgumentException("the console is only opened on this machine", nameof(coreUrl));
        }

        return new Uri(uri, "/console/").ToString() + "#token=" + token;
    }
}
