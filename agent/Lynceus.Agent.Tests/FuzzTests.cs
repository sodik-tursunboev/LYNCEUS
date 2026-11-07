using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Lynceus.Ipc;
using Lynceus.NativeHost;

namespace Lynceus.Agent.Tests;

/// <summary>Random and mutated input at every new door (M7): never an unexpected exception, never a hang, and the next valid request still works.</summary>
public class FuzzTests
{
    private const int Seed = 20261105;
    private static readonly string[] Valid =
    [
        """{"v":1,"type":"status","id":"a1"}""",
        """{"v":1,"type":"check_url","id":"a1","url":"https://example.test/a?b=c"}""",
        """{"v":1,"type":"override","id":"a1","url":"https://example.test/","state":"MALICIOUS","minutes":15}""",
        """{"v":1,"type":"hello","secret":"not-the-real-secret-xx"}""",
    ];

    private static byte[] Mutate(Random rng, byte[] source)
    {
        var bytes = (byte[])source.Clone();
        for (var i = rng.Next(1, 6); i > 0; i--)
        {
            switch (rng.Next(4))
            {
                case 0 when bytes.Length > 0:
                    bytes[rng.Next(bytes.Length)] = (byte)rng.Next(256);
                    break;
                case 1 when bytes.Length > 1:
                    bytes = [.. bytes.Take(rng.Next(bytes.Length))];
                    break;
                case 2:
                    bytes = [.. bytes, .. Enumerable.Range(0, rng.Next(1, 20)).Select(_ => (byte)rng.Next(256))];
                    break;
                default:
                    if (bytes.Length > 0)
                    {
                        var at = rng.Next(bytes.Length);
                        bytes = [.. bytes.Take(at), .. bytes.Skip(at + 1)];
                    }

                    break;
            }
        }

        return bytes;
    }

    [Fact]
    public void The_protocol_parser_never_throws_on_random_or_mutated_messages()
    {
        var rng = new Random(Seed);
        var accepted = 0;
        for (var i = 0; i < 30_000; i++)
        {
            var bytes = i % 3 == 0
                ? rng.GetItems(Enumerable.Range(0, 256).Select(n => (byte)n).ToArray(), rng.Next(0, 200))
                : Mutate(rng, Encoding.UTF8.GetBytes(Valid[rng.Next(Valid.Length)]));
            if (Protocol.TryParse(bytes, out var request, out var error))
            {
                accepted++;
                Assert.NotNull(request);
                Assert.Equal(string.Empty, error);
            }
            else
            {
                Assert.Null(request);
                Assert.False(string.IsNullOrEmpty(error));
            }
        }

        Assert.InRange(accepted, 1, 29_999); // some valid mutations survive, most do not
    }

    [Fact]
    public async Task The_frame_reader_only_ever_returns_a_message_or_a_frame_error()
    {
        var rng = new Random(Seed + 1);
        for (var i = 0; i < 5_000; i++)
        {
            using var stream = new MemoryStream(rng.GetItems(Enumerable.Range(0, 256).Select(n => (byte)n).ToArray(), rng.Next(0, 80)));
            try
            {
                while (await FrameIO.ReadAsync(stream, CancellationToken.None) is not null)
                {
                }
            }
            catch (FrameException)
            {
                // the stated outcome for a bad length or a short read
            }
        }
    }

    [Fact]
    public async Task The_bridge_survives_a_stream_of_garbage_and_always_ends_with_a_stated_exit_code()
    {
        var rng = new Random(Seed + 2);
        var bridge = new Bridge([Endpoints.ExtensionOrigin], _ => Task.FromResult<Stream?>(null));
        for (var i = 0; i < 300; i++)
        {
            using var input = new MemoryStream();
            for (var f = rng.Next(0, 5); f > 0; f--)
            {
                var body = Mutate(rng, Encoding.UTF8.GetBytes(Valid[rng.Next(Valid.Length)]));
                if (body.Length is > 0 and <= FrameIO.MaxFrameBytes)
                {
                    await FrameIO.WriteAsync(input, body, CancellationToken.None);
                }
            }

            input.Write(rng.GetItems(new byte[] { 0, 1, 255, 7 }, rng.Next(0, 6)));
            input.Position = 0;
            using var output = new MemoryStream();
            var exit = await bridge.RunAsync(Endpoints.ExtensionOrigin, input, output, CancellationToken.None);
            Assert.Contains(exit, new[] { 0, 4 });
        }
    }

    [Fact]
    public async Task The_pipe_server_shrugs_off_garbage_after_the_handshake_and_still_answers_the_next_valid_request()
    {
        using var rig = new AgentRig();
        var rng = new Random(Seed + 3);
        for (var round = 0; round < 25; round++)
        {
            await using var pipe = (await rig.ConnectAsync(CancellationToken.None))!;
            for (var i = 0; i < 6; i++)
            {
                var garbage = Mutate(rng, Encoding.UTF8.GetBytes(Valid[rng.Next(Valid.Length)]));
                if (garbage.Length is 0 or > FrameIO.MaxFrameBytes)
                {
                    continue;
                }

                await FrameIO.WriteAsync(pipe, garbage, CancellationToken.None);
                using var cts = new CancellationTokenSource(5000);
                var reply = await FrameIO.ReadAsync(pipe, cts.Token); // an answer, never a hang or a crash
                Assert.NotNull(reply);
                using var parsed = JsonDocument.Parse(reply);
                Assert.Equal(1, parsed.RootElement.GetProperty("v").GetInt32());
            }
        }

        await using var fresh = (await rig.ConnectAsync(CancellationToken.None))!;
        await FrameIO.WriteAsync(fresh, """{"v":1,"type":"status","id":"after"}"""u8.ToArray(), CancellationToken.None);
        using var wait = new CancellationTokenSource(5000);
        Assert.Contains("\"status\"", Encoding.UTF8.GetString((await FrameIO.ReadAsync(fresh, wait.Token))!), StringComparison.Ordinal);
    }

    [Fact]
    public void The_core_client_never_throws_on_hostile_answers()
    {
        var rng = new Random(Seed + 4);
        for (var i = 0; i < 5_000; i++)
        {
            var bytes = rng.GetItems(Enumerable.Range(0, 256).Select(n => (byte)n).ToArray(), rng.Next(0, 300));
            _ = CoreClient.Parse(bytes);
            _ = CoreClient.ParseMailbox(bytes);
            _ = Lynceus.Agent.FileSignatures.Detect(bytes);
            _ = MarkOfTheWeb.HostFrom(Encoding.Latin1.GetString(bytes));
        }
    }
}
