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
    string? Recommended,
    string? Explanation = null,
    IReadOnlyList<string>? Reasons = null);

public sealed record CoreResult(CoreStatus Status, FileVerdict? Verdict = null, string Detail = "");

public sealed record FlaggedMail(double At, string State, int? Score, IReadOnlyList<string> Rules);

/// <summary>What the core says about the live mailbox: a state and the recent flagged mail (rule ids only, never content).</summary>
public sealed record MailboxStatus(string State, IReadOnlyList<FlaggedMail> Flagged);

public sealed record OverrideResult(CoreStatus Status, DateTimeOffset? ExpiresAt = null, string Detail = "");

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

    /// <summary>A URL the browser is about to open, judged by the same engine as everything else.</summary>
    public async Task<CoreResult> CheckUrlAsync(string url, CancellationToken ct)
    {
        using var request = JsonRequest("/v1/urls/analyze", new Dictionary<string, object?> { ["url"] = url });
        if (request is null)
        {
            return new CoreResult(CoreStatus.Rejected, Detail: "the URL cannot be encoded");
        }

        request.Headers.Add("X-Mirage-Source", "BROWSER");
        return await SendAsync(request, ct).ConfigureAwait(false);
    }

    /// <summary>GET /v1/mailbox/status. A failure is a status, never "nothing flagged".</summary>
    public async Task<(CoreStatus Status, MailboxStatus? Value)> MailboxStatusAsync(CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/v1/mailbox/status");
        var (status, body, _) = await SendRawAsync(request, ct).ConfigureAwait(false);
        if (status != CoreStatus.Ok)
        {
            return (status, null);
        }

        var parsed = ParseMailbox(body!);
        return parsed is null ? (CoreStatus.Rejected, null) : (CoreStatus.Ok, parsed);
    }

    internal static MailboxStatus? ParseMailbox(byte[] body)
    {
        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            var state = Text(root, "state", 32);
            if (state is null)
            {
                return null;
            }

            var flagged = new List<FlaggedMail>();
            if (root.TryGetProperty("flagged", out var list) && list.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in list.EnumerateArray().Take(50))
                {
                    var itemState = Text(item, "state", 16);
                    if (itemState is null || !item.TryGetProperty("at", out var at) || at.ValueKind != JsonValueKind.Number)
                    {
                        continue;
                    }

                    var rules = new List<string>();
                    if (item.TryGetProperty("rules", out var ruleList) && ruleList.ValueKind == JsonValueKind.Array)
                    {
                        rules.AddRange(ruleList.EnumerateArray().Take(5).Where(r => r.ValueKind == JsonValueKind.String).Select(r => r.GetString()!).Where(r => r.Length <= 100));
                    }

                    int? score = item.TryGetProperty("score", out var s) && s.ValueKind == JsonValueKind.Number && s.TryGetInt32(out var n) ? n : null;
                    flagged.Add(new FlaggedMail(at.GetDouble(), itemState, score, rules));
                }
            }

            return new MailboxStatus(state, flagged);
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or FormatException)
        {
            return null;
        }
    }

    /// <summary>The user chose to continue to a warned page; the core writes the audit record.</summary>
    public async Task<OverrideResult> OverrideAsync(string url, string? state, int minutes, CancellationToken ct)
    {
        using var request = JsonRequest("/v1/overrides", new Dictionary<string, object?> { ["url"] = url, ["minutes"] = minutes, ["state"] = state });
        if (request is null)
        {
            return new OverrideResult(CoreStatus.Rejected, Detail: "the URL cannot be encoded");
        }

        var (status, body, detail) = await SendRawAsync(request, ct).ConfigureAwait(false);
        if (status != CoreStatus.Ok)
        {
            return new OverrideResult(status, Detail: detail);
        }

        try
        {
            using var document = JsonDocument.Parse(body!);
            var root = document.RootElement;
            return root.GetProperty("recorded").ValueKind == JsonValueKind.True && root.GetProperty("expires_at").TryGetDateTimeOffset(out var expires)
                ? new OverrideResult(CoreStatus.Ok, expires)
                : new OverrideResult(CoreStatus.Rejected, Detail: "not recorded");
        }
        catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            return new OverrideResult(CoreStatus.Rejected, Detail: "unreadable answer");
        }
    }

    private static HttpRequestMessage? JsonRequest(string path, Dictionary<string, object?> fields)
    {
        try
        {
            var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(fields)) };
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            return request;
        }
        catch (ArgumentException)
        {
            return null; // text JSON cannot hold, such as an unpaired surrogate
        }
    }

    private async Task<CoreResult> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var (status, body, detail) = await SendRawAsync(request, ct).ConfigureAwait(false);
        if (status != CoreStatus.Ok)
        {
            return new CoreResult(status, Detail: detail);
        }

        var verdict = Parse(body!);
        return verdict is null
            ? new CoreResult(CoreStatus.Rejected, Detail: "unreadable answer")
            : new CoreResult(CoreStatus.Ok, verdict);
    }

    /// <summary>Status, and the body only when the core answered 200. A failure is never turned into a verdict here.</summary>
    private async Task<(CoreStatus Status, byte[]? Body, string Detail)> SendRawAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var secret = token();
        if (string.IsNullOrEmpty(secret))
        {
            return (CoreStatus.Unauthorized, null, "no API token is configured");
        }

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", secret);
        try
        {
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            return await ReadAsync(response, ct).ConfigureAwait(false);
        }
        catch (HttpRequestException e)
        {
            return (CoreStatus.Unavailable, null, e.GetType().Name + (e.InnerException is { } inner ? "/" + inner.GetType().Name : string.Empty));
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return (CoreStatus.Unavailable, null, "timeout");
        }
    }

    private static async Task<(CoreStatus Status, byte[]? Body, string Detail)> ReadAsync(HttpResponseMessage response, CancellationToken ct)
    {
        var code = (int)response.StatusCode;
        if (code == 401 || code == 403)
        {
            return (CoreStatus.Unauthorized, null, "the core refused the token");
        }

        if (response.StatusCode == HttpStatusCode.RequestEntityTooLarge)
        {
            return (CoreStatus.TooLarge, null, string.Empty);
        }

        if (code == 408 || code == 429 || code >= 500)
        {
            return (CoreStatus.Unavailable, null, $"HTTP {code}");
        }

        if (code != 200)
        {
            return (CoreStatus.Rejected, null, $"HTTP {code}");
        }

        var body = await ReadLimitedAsync(response.Content, ct).ConfigureAwait(false);
        return body is null ? (CoreStatus.Rejected, null, "unreadable answer") : (CoreStatus.Ok, body, string.Empty);
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
            var reasons = new List<string>();
            if (verdict.TryGetProperty("signals", out var signals) && signals.ValueKind == JsonValueKind.Array)
            {
                foreach (var signal in signals.EnumerateArray().Take(64))
                {
                    if (signal.TryGetProperty("rule_id", out var id) && id.ValueKind == JsonValueKind.String && id.GetString() is { Length: <= 100 } rule)
                    {
                        rules.Add(rule);
                        if (reasons.Count < 8 && Text(signal, "description", 300) is { } description)
                        {
                            reasons.Add(description);
                        }
                    }
                }
            }

            return new FileVerdict(
                state,
                score,
                rules,
                Text(root, "reason", 200),
                root.TryGetProperty("inspected", out var inspected) && inspected.ValueKind == JsonValueKind.True,
                root.TryGetProperty("persisted", out var persisted) && persisted.ValueKind == JsonValueKind.True,
                Text(verdict, "recommended_response", 200),
                Text(verdict, "explanation", 600),
                reasons);
        }
        catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            return null;
        }
    }

    private static string? Text(JsonElement parent, string name, int max) =>
        parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String && value.GetString() is { } text && text.Length <= max
            ? text
            : null;
}
