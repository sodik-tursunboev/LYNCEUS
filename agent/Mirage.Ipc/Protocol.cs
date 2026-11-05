using System.Text.Json;
using System.Text.RegularExpressions;

namespace Mirage.Ipc;

public enum RequestType
{
    Hello,
    Status,
    CheckUrl,
    Override,
}

/// <summary>A validated message from the extension (or, for Hello, from the native host).</summary>
public sealed record Request(RequestType Type, string? Id, string? Url, string? State, int Minutes, string? Secret);

/// <summary>
/// The messages between extension, native host and agent: small, versioned, strictly validated.
/// Anything with an unknown type, an unknown field, a wrong type or an odd size is refused, so
/// the agent never acts on a message it does not fully understand.
/// </summary>
public static partial class Protocol
{
    public const int Version = 1;
    public const int MaxUrlChars = 8192;

    public const string UnknownType = "unknown_type";
    public const string Malformed = "malformed";
    public const string AgentUnavailable = "agent_unavailable";
    public const string AgentTimeout = "agent_timeout";
    public const string OriginRefused = "origin_refused";

    private static readonly Dictionary<string, (RequestType Type, string[] Required, string[] Optional)> Shapes = new()
    {
        ["hello"] = (RequestType.Hello, ["secret"], []),
        ["status"] = (RequestType.Status, ["id"], []),
        ["check_url"] = (RequestType.CheckUrl, ["id", "url"], []),
        ["override"] = (RequestType.Override, ["id", "url"], ["state", "minutes"]),
    };

    private static readonly HashSet<string> States = ["MALICIOUS", "SUSPICIOUS", "BENIGN", "UNKNOWN", "ERROR"];

    [GeneratedRegex("^[A-Za-z0-9._-]{1,64}$")]
    private static partial Regex IdPattern();

    /// <summary>Parse and validate one message. On failure <paramref name="error"/> is a short code.</summary>
    public static bool TryParse(ReadOnlySpan<byte> json, out Request? request, out string error)
    {
        request = null;
        error = Malformed;
        try
        {
            using var document = JsonDocument.Parse(json.ToArray(), new JsonDocumentOptions { MaxDepth = 4 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            var fields = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
            {
                if (!fields.TryAdd(property.Name, property.Value))
                {
                    return false; // a repeated key
                }
            }

            if (!fields.TryGetValue("v", out var version) || version.ValueKind != JsonValueKind.Number || !version.TryGetInt32(out var v) || v != Version)
            {
                return false;
            }

            if (!fields.TryGetValue("type", out var typeElement) || typeElement.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            if (!Shapes.TryGetValue(typeElement.GetString()!, out var shape))
            {
                error = UnknownType;
                return false;
            }

            var allowed = new HashSet<string>(["v", "type", .. shape.Required, .. shape.Optional]);
            if (fields.Keys.Any(k => !allowed.Contains(k)) || shape.Required.Any(k => !fields.ContainsKey(k)))
            {
                return false;
            }

            string? id = Text(fields, "id", out var okId);
            string? url = Text(fields, "url", out var okUrl);
            string? state = Text(fields, "state", out var okState);
            string? secret = Text(fields, "secret", out var okSecret);
            var minutes = 15;
            if (fields.TryGetValue("minutes", out var m) && (m.ValueKind != JsonValueKind.Number || !m.TryGetInt32(out minutes) || minutes is < 1 or > 60))
            {
                return false;
            }

            if (!okId || !okUrl || !okState || !okSecret
                || (id is not null && !IdPattern().IsMatch(id))
                || (url is not null && (url.Length is 0 or > MaxUrlChars || url.Any(char.IsControl)))
                || (state is not null && !States.Contains(state))
                || (secret is not null && secret.Length is < 16 or > 256))
            {
                return false;
            }

            request = new Request(shape.Type, id, url, state, minutes, secret);
            error = string.Empty;
            return true;
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or ArgumentException)
        {
            return false;
        }
    }

    /// <summary>True for the agent's answer to a correct handshake.</summary>
    public static bool IsHelloReply(ReadOnlySpan<byte> json)
    {
        try
        {
            using var document = JsonDocument.Parse(json.ToArray(), new JsonDocumentOptions { MaxDepth = 4 });
            var root = document.RootElement;
            return root.ValueKind == JsonValueKind.Object
                && root.TryGetProperty("type", out var type) && type.ValueKind == JsonValueKind.String && type.GetString() == "hello"
                && root.TryGetProperty("ok", out var ok) && ok.ValueKind == JsonValueKind.True;
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or ArgumentException)
        {
            return false;
        }
    }

    public static byte[] Hello() => Build(w => w.WriteBoolean("ok", true), "hello", null);

    public static byte[] Error(string? id, string code) => Build(w => w.WriteString("error", code), "error", id);

    /// <summary>A reply built from a type name and optional fields; every reply carries the version.</summary>
    public static byte[] Build(Action<Utf8JsonWriter> fields, string type, string? id)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("v", Version);
            writer.WriteString("type", type);
            if (id is not null)
            {
                writer.WriteString("id", id);
            }

            fields(writer);
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    private static string? Text(Dictionary<string, JsonElement> fields, string name, out bool ok)
    {
        ok = true;
        if (!fields.TryGetValue(name, out var value))
        {
            return null;
        }

        if (value.ValueKind != JsonValueKind.String)
        {
            ok = false;
            return null;
        }

        return value.GetString();
    }
}
