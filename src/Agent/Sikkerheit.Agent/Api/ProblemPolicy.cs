using Sikkerheit.Contracts;

namespace Sikkerheit.Agent.Api;

/// <summary>Operations of the agent API.</summary>
public enum AgentOperation
{
    CreateChallenge,
    Enroll,
    CreateSession,
    CheckIn,
    SubmitScan,
}

/// <summary>Actions of the agent from the table "Ошибки и действия агента" (05).</summary>
[Flags]
public enum AgentActions
{
    None = 0,
    SkipRequest = 1,
    DropBatch = 2,
    RefreshConfiguration = 4,
    StopUntilUpgrade = 8,
    ResyncSequence = 16,
    IdentityStop = 32,
    SuspendUntilActive = 64,
    AwaitEnrollmentKey = 128,
    NewChallenge = 256,
    RenewSession = 512,
    Reenroll = 1024,
    StopUntilReinstall = 2048,
    RetryAfter = 4096,
    RetryBackoff = 8192,
}

/// <summary>Reaction of the agent to an answer of the server by the code of Problem.</summary>
public static class ProblemPolicy
{
    private static readonly Dictionary<string, string> Names = new(StringComparer.Ordinal)
    {
        ["skip_request"] = nameof(AgentActions.SkipRequest),
        ["drop_batch"] = nameof(AgentActions.DropBatch),
        ["refresh_configuration"] = nameof(AgentActions.RefreshConfiguration),
        ["stop_until_upgrade"] = nameof(AgentActions.StopUntilUpgrade),
        ["resync_sequence"] = nameof(AgentActions.ResyncSequence),
        ["identity_stop"] = nameof(AgentActions.IdentityStop),
        ["suspend_until_active"] = nameof(AgentActions.SuspendUntilActive),
        ["await_enrollment_key"] = nameof(AgentActions.AwaitEnrollmentKey),
        ["new_challenge"] = nameof(AgentActions.NewChallenge),
        ["renew_session"] = nameof(AgentActions.RenewSession),
        ["reenroll"] = nameof(AgentActions.Reenroll),
        ["stop_until_reinstall"] = nameof(AgentActions.StopUntilReinstall),
        ["retry_after"] = nameof(AgentActions.RetryAfter),
        ["retry_backoff"] = nameof(AgentActions.RetryBackoff),
    };

    /// <summary>
    /// Actions of the code for the operation. The text of the catalog (<see cref="Catalog.Problems"/>, generated from the 05 table) is the
    /// single source: "operation: actions; other agent operations: actions" and the list "a + b".
    /// </summary>
    public static AgentActions Resolve(string code, AgentOperation operation, bool hasRetryAfter)
    {
        if (!Catalog.Problems.TryGetValue(code, out var problem) || problem.AgentAction == "—")
        {
            return AgentActions.RetryBackoff;
        }
        var text = problem.AgentAction;
        if (code == "temporarily_unavailable")
        {
            return hasRetryAfter ? AgentActions.RetryAfter : AgentActions.RetryBackoff;
        }
        var segments = text.Split("; ", StringSplitOptions.RemoveEmptyEntries);
        var chosen = segments.Length == 1 && !segments[0].Contains(": ", StringComparison.Ordinal)
            ? segments[0]
            : SelectSegment(segments, operation);
        return chosen is null ? AgentActions.None : Parse(chosen);
    }

    /// <summary>Tokens of the action text of the catalog, to check the table against the contract.</summary>
    public static IReadOnlyCollection<string> CatalogTokens(string code) =>
        Catalog.Problems[code].AgentAction
            .Split([' ', ';', '+', ':'], StringSplitOptions.RemoveEmptyEntries)
            .Where(Names.ContainsKey)
            .ToHashSet(StringComparer.Ordinal);

    private static string? SelectSegment(string[] segments, AgentOperation operation)
    {
        var name = operation switch
        {
            AgentOperation.SubmitScan => "submitScan",
            AgentOperation.Enroll => "enrollAgent",
            _ => null,
        };
        string? other = null;
        foreach (var segment in segments)
        {
            var cut = segment.IndexOf(": ", StringComparison.Ordinal);
            var label = segment[..cut];
            var actions = segment[(cut + 2)..];
            if (label == name)
            {
                return actions;
            }
            if (label.StartsWith("прочие", StringComparison.Ordinal))
            {
                other = actions;
            }
        }
        return other;
    }

    private static AgentActions Parse(string text)
    {
        var result = AgentActions.None;
        foreach (var token in text.Split(['+', ' '], StringSplitOptions.RemoveEmptyEntries))
        {
            if (Names.TryGetValue(token, out var name))
            {
                result |= Enum.Parse<AgentActions>(name);
            }
        }
        return result;
    }
}
