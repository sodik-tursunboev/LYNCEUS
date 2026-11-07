using System.Buffers.Binary;

namespace Lynceus.Ipc;

public sealed class FrameException(string message) : Exception(message);

/// <summary>
/// One message = a 32-bit little-endian length (native order on Windows, as the browser's native
/// messaging uses) followed by that many bytes of UTF-8 JSON. The same framing is used on the
/// browser's stdio and on the pipe to the agent, so the host can pass a message through unchanged.
/// </summary>
public static class FrameIO
{
    /// <summary>Largest message either side will read or write. Real messages are a few hundred bytes.</summary>
    public const int MaxFrameBytes = 64 * 1024;

    /// <summary>The next message, or null if the stream ended cleanly between messages.</summary>
    public static async Task<byte[]?> ReadAsync(Stream stream, CancellationToken ct)
    {
        var header = new byte[4];
        var got = await ReadFullAsync(stream, header, ct).ConfigureAwait(false);
        if (got == 0)
        {
            return null;
        }

        if (got < header.Length)
        {
            throw new FrameException("the stream ended inside a length header");
        }

        var length = BinaryPrimitives.ReadUInt32LittleEndian(header);
        if (length == 0 || length > MaxFrameBytes)
        {
            throw new FrameException("a message length outside 1.." + MaxFrameBytes);
        }

        var body = new byte[length];
        if (await ReadFullAsync(stream, body, ct).ConfigureAwait(false) < body.Length)
        {
            throw new FrameException("the stream ended inside a message");
        }

        return body;
    }

    /// <summary>Header and body in one write, so two writers cannot interleave half-messages.</summary>
    public static async Task WriteAsync(Stream stream, ReadOnlyMemory<byte> body, CancellationToken ct)
    {
        if (body.Length is 0 or > MaxFrameBytes)
        {
            throw new FrameException("a message length outside 1.." + MaxFrameBytes);
        }

        var buffer = new byte[4 + body.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer, (uint)body.Length);
        body.CopyTo(buffer.AsMemory(4));
        await stream.WriteAsync(buffer, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    private static async Task<int> ReadFullAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(total), ct).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total;
    }
}
