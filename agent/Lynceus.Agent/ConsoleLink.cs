namespace Lynceus.Agent;

/// <summary>
/// The address that opens the console already signed in. It carries a one-time code (H1 A1), never the API
/// token: the code is worth one console session, for 60 seconds, so the copy a browser's history may keep is
/// already spent. It travels in the address fragment, which the browser never sends to any server.
/// </summary>
public static class ConsoleLink
{
    public static string Build(string coreUrl, string code)
    {
        var uri = new Uri(coreUrl);
        if (!CoreHttp.IsLoopbackUrl(uri))
        {
            throw new ArgumentException("the console is only opened on this machine", nameof(coreUrl));
        }

        return new Uri(uri, "/console/").ToString() + "#code=" + code;
    }

    /// <summary>Ask the running core for a code and build the link; null (with the reason) when the core cannot be reached.</summary>
    public static async Task<(string? Link, string Problem)> FetchAsync(string coreUrl, string token, CancellationToken ct)
    {
        using var http = CoreHttp.Create(new Uri(coreUrl), TimeSpan.FromSeconds(10));
        var (status, code) = await new CoreClient(http, () => token).ConsoleCodeAsync(ct).ConfigureAwait(false);
        return code is null ? (null, $"the core did not give a sign-in code ({status}); is it running?") : (Build(coreUrl, code), "");
    }
}
