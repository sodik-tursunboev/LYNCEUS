using System.Net;
using System.Net.Sockets;

namespace Mirage.Agent;

/// <summary>
/// The HTTP client for the local core. It can only reach this machine: the URL is checked, the
/// address every connection resolves to is checked again, there is no proxy and no redirect, so
/// neither a file nor the bearer token can be sent anywhere else.
/// </summary>
public static class CoreHttp
{
    public static bool IsLoopbackUrl(Uri uri)
    {
        if (!uri.IsAbsoluteUri || uri.Scheme != Uri.UriSchemeHttp || uri.UserInfo.Length > 0)
        {
            return false;
        }

        var host = uri.DnsSafeHost;
        return host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
            || (IPAddress.TryParse(host, out var ip) && IPAddress.IsLoopback(ip));
    }

    public static HttpClient Create(Uri baseAddress, TimeSpan timeout)
    {
        if (!IsLoopbackUrl(baseAddress))
        {
            throw new ArgumentException("the core address must be on this machine", nameof(baseAddress));
        }

        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            UseCookies = false,
            ConnectTimeout = TimeSpan.FromSeconds(2),
            ConnectCallback = ConnectAsync,
        };
        return new HttpClient(handler, disposeHandler: true) { BaseAddress = baseAddress, Timeout = timeout };
    }

    internal static async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken ct)
    {
        var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, ct).ConfigureAwait(false);
        if (addresses.Length == 0 || addresses.Any(a => !IPAddress.IsLoopback(a)))
        {
            throw new HttpRequestException("the core address is not on this machine: " + string.Join(",", addresses.Select(a => a.ToString())));
        }

        var socket = new Socket(addresses[0].AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new IPEndPoint(addresses[0], context.DnsEndPoint.Port), ct).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
