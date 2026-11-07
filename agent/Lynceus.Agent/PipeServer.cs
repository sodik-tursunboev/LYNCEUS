using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Lynceus.Ipc;

namespace Lynceus.Agent;

/// <summary>
/// The agent's door for the native host. The pipe is current-user only (the operating system
/// refuses other users and, for an elevated server, unelevated callers' impersonation tricks),
/// and the first message must carry the per-install secret. A wrong or missing secret, an
/// oversize or unreadable frame, or a silent client gets the connection closed without a reply.
/// </summary>
public sealed class PipeServer(string pipeName, string secret, RequestHandler handler, ILogger log)
{
    internal const int MaxClients = 4;
    internal static readonly TimeSpan HelloDeadline = TimeSpan.FromSeconds(2);

    internal static TimeSpan RetryEvery { get; set; } = TimeSpan.FromSeconds(5);

    private int clients;
    private long refused;
    private int busyRounds;

    public long Refused => Interlocked.Read(ref refused);

    public async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream server;
            try
            {
                server = new NamedPipeServerStream(
                    pipeName, PipeDirection.InOut, MaxClients + 2, PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                busyRounds = 0;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // Another program holds the pipe name, so the browser extension cannot reach this agent. Say so
                // (it would otherwise just look like "protection off") and keep trying: the name may free up.
                if (busyRounds++ % 12 == 0)
                {
                    log.LogError("the agent's pipe name is taken by another program ({Type}); the browser extension cannot reach the agent until it is free", e.GetType().Name);
                }

                try
                {
                    await Task.Delay(RetryEvery, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }

                continue;
            }

            try
            {
                await server.WaitForConnectionAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                await server.DisposeAsync().ConfigureAwait(false);
                return;
            }
            catch (IOException)
            {
                await server.DisposeAsync().ConfigureAwait(false);
                continue;
            }

            if (Interlocked.Increment(ref clients) > MaxClients)
            {
                Interlocked.Decrement(ref clients);
                Interlocked.Increment(ref refused);
                await server.DisposeAsync().ConfigureAwait(false);
                continue;
            }

            _ = Task.Run(() => ServeAsync(server, ct), ct);
        }
    }

    internal async Task ServeAsync(Stream stream, CancellationToken ct)
    {
        try
        {
            await using (stream.ConfigureAwait(false))
            {
                if (!await HandshakeAsync(stream, ct).ConfigureAwait(false))
                {
                    Interlocked.Increment(ref refused);
                    return;
                }

                var bad = 0;
                while (!ct.IsCancellationRequested)
                {
                    var frame = await FrameIO.ReadAsync(stream, ct).ConfigureAwait(false);
                    if (frame is null)
                    {
                        return; // the host went away
                    }

                    if (!Protocol.TryParse(frame, out var request, out var error) || request!.Type == RequestType.Hello)
                    {
                        await FrameIO.WriteAsync(stream, Protocol.Error(null, request is null ? error : Protocol.UnknownType), ct).ConfigureAwait(false);
                        if (++bad >= 10)
                        {
                            return;
                        }

                        continue;
                    }

                    await FrameIO.WriteAsync(stream, await handler.HandleAsync(request, ct).ConfigureAwait(false), ct).ConfigureAwait(false);
                }
            }
        }
        catch (Exception e) when (e is FrameException or IOException or OperationCanceledException or ObjectDisposedException)
        {
            // a client that misbehaves or leaves is not an agent failure
        }
        catch (Exception e)
        {
            log.LogError("a pipe client failed the agent unexpectedly ({Type})", e.GetType().Name);
        }
        finally
        {
            Interlocked.Decrement(ref clients);
        }
    }

    private async Task<bool> HandshakeAsync(Stream stream, CancellationToken ct)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(HelloDeadline);
        try
        {
            var frame = await FrameIO.ReadAsync(stream, limit.Token).ConfigureAwait(false);
            if (frame is null
                || !Protocol.TryParse(frame, out var hello, out _)
                || hello!.Type != RequestType.Hello
                || !SecretMatches(hello.Secret))
            {
                return false;
            }

            await FrameIO.WriteAsync(stream, Protocol.Hello(), limit.Token).ConfigureAwait(false);
            return true;
        }
        catch (Exception e) when (e is FrameException or IOException or OperationCanceledException)
        {
            return false;
        }
    }

    private bool SecretMatches(string? given) =>
        given is not null && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(given), Encoding.UTF8.GetBytes(secret));
}
