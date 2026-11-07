using System.IO.Pipes;
using Lynceus.Ipc;
using Lynceus.NativeHost;

// Started by the browser: argument 1 is the caller's origin, stdin/stdout carry the messages.
// Nothing here may crash or hang: the browser would show a generic failure and Windows Error
// Reporting would delay the exit, so every path ends in a clean return.
try
{
    var dataDir = Endpoints.DataDir();
    var bridge = new Bridge([Endpoints.ExtensionOrigin], ct => Connector.ConnectFromDiskAsync(dataDir, ct));
    using var stdin = Console.OpenStandardInput();
    using var stdout = Console.OpenStandardOutput();
    return await bridge.RunAsync(args.FirstOrDefault(), stdin, stdout, CancellationToken.None);
}
catch (Exception)
{
    return 1;
}

namespace Lynceus.NativeHost
{
    internal static class Connector
    {
        private static readonly TimeSpan ConnectTimeout = TimeSpan.FromMilliseconds(300);

        internal static Task<Stream?> ConnectFromDiskAsync(string dataDir, CancellationToken ct) =>
            Endpoints.ReadSecret(Endpoints.SecretPath(dataDir)) is { } secret
                ? ConnectAsync(Endpoints.PipeName(), secret, ct)
                : Task.FromResult<Stream?>(null);

        /// <summary>Connect to the agent's pipe and prove we know the install secret. Null if the agent is not there.</summary>
        internal static async Task<Stream?> ConnectAsync(string pipeName, string secret, CancellationToken ct)
        {
            var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            try
            {
                using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
                limit.CancelAfter(ConnectTimeout);
                await pipe.ConnectAsync(limit.Token).ConfigureAwait(false);
                var hello = Protocol.Build(w => w.WriteString("secret", secret), "hello", null);
                await FrameIO.WriteAsync(pipe, hello, limit.Token).ConfigureAwait(false);
                using var reply = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                var answer = await FrameIO.ReadAsync(pipe, reply.Token).ConfigureAwait(false);
                if (answer is not null && Protocol.IsHelloReply(answer))
                {
                    return pipe;
                }
            }
            catch (Exception e) when (e is IOException or FrameException or OperationCanceledException or UnauthorizedAccessException)
            {
                // not there, not ours, or too slow
            }

            await pipe.DisposeAsync().ConfigureAwait(false);
            return null;
        }
    }
}
