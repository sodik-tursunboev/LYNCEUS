using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Mirage.Agent;

public enum CoreStatus
{
    Ok,

    /// <summary>Not reachable, overloaded or failing: try again later. Never a verdict.</summary>
    Unavailable,

    /// <summary>No token, or the core refused it.</summary>
    Unauthorized,

    /// <summary>The core says the file is over its limit for being opened.</summary>
    TooLarge,

    /// <summary>The core refused the request or its answer was unreadable: retrying will not help.</summary>
    Rejected,
}

/// <summary>What the core said about one file. State is one of the five verdicts, never anything else.</summary>
public sealed record FileVerdict(
    string State,
    int? RiskScore,
    IReadOnlyList<string> Rules,
    string? Reason,
    bool Inspected,
    bool Persisted,
    string? Recommended);

public sealed record CoreResult(CoreStatus Status, FileVerdict? Verdict = null, string Detail = "");

/// <summary>The agent's side of POST /v1/files/analyze and /v1/files/check.</summary>
public sealed class CoreClient(HttpClient http, Func<string?> token)
{
    private const int MaxResponseBytes = 1024 * 1024;
    private static readonly HashSet<string> States = ["MALICIOUS", "SUSPICIOUS", "BENIGN", "UNKNOWN", "ERROR"];

    /// <summary>The file's bytes go to the core, which opens them in its sandbox.</summary>
    public async Task<CoreResult> AnalyzeAsync(
        string name, string sha256, string? originHost, ReadOnlyMemory<byte> data, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/files/analyze") { Content = new ReadOnlyMemoryContent(data) };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        request.Headers.Add("X-Mirage-Name", Uri.EscapeDataString(Clean(name)));
        request.Headers.Add("X-Mirage-Sha256", sha256);
        if (originHost is not null)
        {
            request.Headers.Add("X-Mirage-Origin-Host", originHost);
        }

        return await SendAsync(request, ct).ConfigureAwait(false);
    }

    /// <summary>Only what the agent knows: name, size, hash, type, origin host.</summary>
    public async Task<CoreResult> CheckAsync(
        string name, long size, string sha256, string? magic, string? originHost, CancellationToken ct)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object?>
        {
            ["name"] = Clean(name),
            ["size"] = size,
            ["sha256"] = sha256,
            ["magic"] = magic,
            ["origin_host"] = originHost,
        });
        using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/files/check") { Content = new ByteArrayContent(body) };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return await SendAsync(request, ct).ConfigureAwait(false);
    }

    /// <summary>A file name cut to what the core accepts, with unpaired surrogates (legal in NTFS) replaced.</summary>
    internal static string Clean(string name)
    {
        var builder = new StringBuilder(name.Length);
        for (var i = 0; i < name.Length; i++)
        {
            var c = name[i];
            if (char.IsHighSurrogate(c) && i + 1 < name.Length && char.IsLowSurrogate(name[i + 1]))
            {
                builder.Append(c).Append(name[++i]);
            }
            else
            {
                builder.Append(char.IsSurrogate(c) || c == '\0' ? '�' : c);
            }
        }

        var clean = builder.ToString();
        return clean.Length <= 1000 ? clean : clean[^1000..];
    }

    private async Task<CoreResult> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var secret = token();
        if (string.IsNullOrEmpty(secret))
        {
            return new CoreResult(CoreStatus.Unauthorized, Detail: "no API token is configured");
        }

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", secret);
        try
        {
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            return await ReadAsync(response, ct).ConfigureAwait(false);
        }
        catch (HttpRequestException e)
        {
            return new CoreResult(CoreStatus.Unavailable, Detail: e.GetType().Name + (e.InnerException is { } inner ? "/" + inner.GetType().Name + ": " + inner.Message : ": " + e.Message));
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new CoreResult(CoreStatus.Unavailable, Detail: "timeout");
        }
    }

    private static async Task<CoreResult> ReadAsync(HttpResponseMessage response, CancellationToken ct)
    {
        var code = (int)response.StatusCode;
        if (code == 401 || code == 403)
        {
            return new CoreResult(CoreStatus.Unauthorized, Detail: "the core refused the token");
        }

        if (response.StatusCode == HttpStatusCode.RequestEntityTooLarge)
        {
            return new CoreResult(CoreStatus.TooLarge);
        }

        if (code == 408 || code == 429 || code >= 500)
        {
            return new CoreResult(CoreStatus.Unavailable, Detail: $"HTTP {code}");
        }

        if (code != 200)
        {
            return new CoreResult(CoreStatus.Rejected, Detail: $"HTTP {code}");
        }

        var body = await ReadLimitedAsync(response.Content, ct).ConfigureAwait(false);
        var verdict = body is null ? null : Parse(body);
        return verdict is null
            ? new CoreResult(CoreStatus.Rejected, Detail: "unreadable answer")
            : new CoreResult(CoreStatus.Ok, verdict);
    }

    private static async Task<byte[]?> ReadLimitedAsync(HttpContent content, CancellationToken ct)
    {
        if (content.Headers.ContentLength > MaxResponseBytes)
        {
            return null;
        }

        await using var stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int read;
        while ((read = await stream.ReadAsync(chunk, ct).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > MaxResponseBytes)
            {
                return null;
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    internal static FileVerdict? Parse(byte[] body)
    {
        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            var verdict = root.GetProperty("verdict");
            var state = verdict.GetProperty("state").GetString();
            if (state is null || !States.Contains(state))
            {
                return null;
            }

            int? score = verdict.TryGetProperty("risk_score", out var s) && s.ValueKind == JsonValueKind.Number ? s.GetInt32() : null;
            var rules = new List<string>();
            if (verdict.TryGetProperty("signals", out var signals) && signals.ValueKind == JsonValueKind.Array)
            {
                foreach (var signal in signals.EnumerateArray().Take(64))
                {
                    if (signal.TryGetProperty("rule_id", out var id) && id.GetString() is { Length: <= 100 } rule)
                    {
                        rules.Add(rule);
                    }
                }
            }

            return new FileVerdict(
                state,
                score,
                rules,
                Text(root, "reason"),
                root.TryGetProperty("inspected", out var inspected) && inspected.ValueKind == JsonValueKind.True,
                root.TryGetProperty("persisted", out var persisted) && persisted.ValueKind == JsonValueKind.True,
                Text(verdict, "recommended_response"));
        }
        catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            return null;
        }
    }

    private static string? Text(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String && value.GetString() is { Length: <= 200 } text
            ? text
            : null;
}
