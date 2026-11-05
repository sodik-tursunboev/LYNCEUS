using System.Text.Json;
using Mirage.Ipc;

namespace Mirage.Agent;

/// <summary>Answers the extension's validated requests. A core failure is reported as such, never as a verdict.</summary>
public sealed class RequestHandler(CoreClient core, Func<PipelineStats> stats)
{
    internal const string CoreUnavailable = "core_unavailable";
    internal const string Rejected = "rejected";
    internal const string OverrideNotRecorded = "override_not_recorded";

    private static readonly TimeSpan CoreDeadline = TimeSpan.FromSeconds(4);

    public async Task<byte[]> HandleAsync(Request request, CancellationToken ct)
    {
        switch (request.Type)
        {
            case RequestType.Status:
                var s = stats();
                return Protocol.Build(
                    w =>
                    {
                        w.WriteString("agent", "ok");
                        w.WriteNumber("judged", s.Judged);
                        w.WriteNumber("waiting", s.WaitingForCore);
                    },
                    "status",
                    request.Id);
            case RequestType.CheckUrl:
                return await CheckUrlAsync(request, ct).ConfigureAwait(false);
            case RequestType.Override:
                return await OverrideAsync(request, ct).ConfigureAwait(false);
            default:
                return Protocol.Error(request.Id, Protocol.UnknownType);
        }
    }

    private async Task<byte[]> CheckUrlAsync(Request request, CancellationToken ct)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(CoreDeadline);
        var result = await core.CheckUrlAsync(request.Url!, limit.Token).ConfigureAwait(false);
        if (result.Status != CoreStatus.Ok)
        {
            return Protocol.Error(request.Id, result.Status is CoreStatus.Rejected or CoreStatus.TooLarge ? Rejected : CoreUnavailable);
        }

        var v = result.Verdict!;
        return Protocol.Build(
            w =>
            {
                w.WriteString("state", v.State);
                if (v.RiskScore is { } score)
                {
                    w.WriteNumber("score", score);
                }
                else
                {
                    w.WriteNull("score");
                }

                w.WriteString("recommended", v.Recommended);
                w.WriteString("explanation", v.Explanation);
                w.WriteStartArray("reasons");
                foreach (var reason in v.Reasons ?? [])
                {
                    w.WriteStringValue(reason);
                }

                w.WriteEndArray();
            },
            "verdict",
            request.Id);
    }

    private async Task<byte[]> OverrideAsync(Request request, CancellationToken ct)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(CoreDeadline);
        var result = await core.OverrideAsync(request.Url!, request.State, request.Minutes, limit.Token).ConfigureAwait(false);
        if (result.Status != CoreStatus.Ok || result.ExpiresAt is not { } expires)
        {
            // the audit record is part of the override: no record, no continue
            return Protocol.Error(request.Id, OverrideNotRecorded);
        }

        return Protocol.Build(w => w.WriteString("expires_at", expires), "override_ok", request.Id);
    }
}
