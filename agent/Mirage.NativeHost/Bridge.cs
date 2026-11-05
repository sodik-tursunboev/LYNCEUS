using System.Diagnostics;
using Mirage.Ipc;

namespace Mirage.NativeHost;

/// <summary>
/// The program the browser starts for the extension. It passes validated messages between the
/// browser's stdio and the agent's pipe and nothing else. It never waits long, never crashes on
/// bad input, and exits when the browser closes its end. When the agent is not there it answers
/// at once with "agent_unavailable", which the extension shows as "not protected".
/// </summary>
public sealed class Bridge(IReadOnlyList<string> allowedOrigins, Func<CancellationToken, Task<Stream?>> connect)
{
    internal static readonly TimeSpan AgentReplyDeadline = TimeSpan.FromSeconds(8);
    internal static readonly TimeSpan RetryGap = TimeSpan.FromSeconds(1);

    private Stream? agent;
    private long retryAt;

    /// <summary>Returns the process exit code: 0 for a normal end, otherwise a reason.</summary>
    public async Task<int> RunAsync(string? origin, Stream stdin, Stream stdout, CancellationToken ct)
    {
        if (origin is null || !allowedOrigins.Contains(origin, StringComparer.Ordinal))
        {
            await TryWriteAsync(stdout, Protocol.Error(null, Protocol.OriginRefused), ct).ConfigureAwait(false);
            return 3;
        }

        try
        {
            while (!ct.IsCancellationRequested)
            {
                var frame = await FrameIO.ReadAsync(stdin, ct).ConfigureAwait(false);
                if (frame is null)
                {
                    return 0; // the browser closed the port
                }

                byte[] reply;
                if (!Protocol.TryParse(frame, out var request, out var error))
                {
                    reply = Protocol.Error(null, error);
                }
                else if (request!.Type == RequestType.Hello)
                {
                    reply = Protocol.Error(request.Id, Protocol.UnknownType); // the handshake is the host's own business
                }
                else
                {
                    reply = await ForwardAsync(request, frame, ct).ConfigureAwait(false);
                }

                await FrameIO.WriteAsync(stdout, reply, ct).ConfigureAwait(false);
            }

            return 0;
        }
        catch (FrameException)
        {
            return 4; // a bad length cannot be resynchronised
        }
        catch (Exception e) when (e is IOException or OperationCanceledException or ObjectDisposedException)
        {
            return 0;
        }
        finally
        {
            if (agent is not null)
            {
                await agent.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private async Task<byte[]> ForwardAsync(Request request, byte[] frame, CancellationToken ct)
    {
        var stream = await EnsureAgentAsync(ct).ConfigureAwait(false);
        if (stream is null)
        {
            return Protocol.Error(request.Id, Protocol.AgentUnavailable);
        }

        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(AgentReplyDeadline);
        try
        {
            await FrameIO.WriteAsync(stream, frame, limit.Token).ConfigureAwait(false);
            return await FrameIO.ReadAsync(stream, limit.Token).ConfigureAwait(false)
                ?? throw new IOException("the agent closed the pipe");
        }
        catch (Exception e) when (e is IOException or FrameException or ObjectDisposedException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            await DropAgentAsync().ConfigureAwait(false);
            return Protocol.Error(request.Id, e is OperationCanceledException ? Protocol.AgentTimeout : Protocol.AgentUnavailable);
        }
    }

    private async Task<Stream?> EnsureAgentAsync(CancellationToken ct)
    {
        if (agent is not null)
        {
            return agent;
        }

        if (Stopwatch.GetTimestamp() < Interlocked.Read(ref retryAt))
        {
            return null; // it just failed; answer at once rather than wait again
        }

        agent = await connect(ct).ConfigureAwait(false);
        if (agent is null)
        {
            Interlocked.Exchange(ref retryAt, Stopwatch.GetTimestamp() + (long)(RetryGap.TotalSeconds * Stopwatch.Frequency));
        }

        return agent;
    }

    private async Task DropAgentAsync()
    {
        if (agent is not null)
        {
            await agent.DisposeAsync().ConfigureAwait(false);
            agent = null;
        }

        Interlocked.Exchange(ref retryAt, Stopwatch.GetTimestamp() + (long)(RetryGap.TotalSeconds * Stopwatch.Frequency));
    }

    private static async Task TryWriteAsync(Stream stdout, byte[] frame, CancellationToken ct)
    {
        try
        {
            await FrameIO.WriteAsync(stdout, frame, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException)
        {
            // the browser is already gone
        }
    }
}
