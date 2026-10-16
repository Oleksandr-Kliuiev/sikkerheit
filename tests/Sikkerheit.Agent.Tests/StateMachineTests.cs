using Sikkerheit.Agent.Api;
using Sikkerheit.Agent.Runtime;
using Sikkerheit.Contracts;

namespace Sikkerheit.Agent.Tests;

/// <summary>Model test of the table "Конечный автомат агента" (05): every row and every code of the catalog in every state.</summary>
public sealed class StateMachineTests
{
    private static readonly AgentState[] States = Enum.GetValues<AgentState>();

    private static IEnumerable<string> AgentCodes => Catalog.Problems.Values.Where(p => p.AgentAction != "—").Select(p => p.Code);

    private static AgentPosition From(AgentState state) =>
        state == AgentState.Backoff ? new AgentPosition(state, AgentState.Active) : AgentPosition.Of(state);

    private static AgentState After(AgentState state, string code, AgentOperation operation, bool retryAfter = false)
    {
        var actions = ProblemPolicy.Resolve(code, operation, retryAfter);
        return AgentStateMachine.OnFailure(From(state), actions, operation, code).State;
    }

    [Fact]
    public void Every_code_of_the_catalog_in_every_state_gives_a_defined_state_and_revoked_is_absorbing()
    {
        foreach (var state in States)
        {
            foreach (var code in AgentCodes)
            {
                foreach (var operation in Enum.GetValues<AgentOperation>())
                {
                    var next = After(state, code, operation);
                    Assert.True(Enum.IsDefined(next), $"{state} {code} {operation}");
                    if (state == AgentState.Revoked)
                    {
                        Assert.Equal(AgentState.Revoked, next);
                    }
                }
            }
        }
    }

    [Fact]
    public void Actions_of_the_policy_cover_the_action_text_of_the_catalog_for_every_code()
    {
        foreach (var code in AgentCodes)
        {
            var union = Enum.GetValues<AgentOperation>()
                .SelectMany(op => new[] { false, true }.Select(r => ProblemPolicy.Resolve(code, op, r)))
                .Aggregate(AgentActions.None, (a, b) => a | b);
            var tokens = ProblemPolicy.CatalogTokens(code);
            var names = Enum.GetValues<AgentActions>().Where(a => a != AgentActions.None && union.HasFlag(a))
                .Select(a => string.Concat(a.ToString().Select((c, i) => i > 0 && char.IsUpper(c) ? "_" + char.ToLowerInvariant(c) : char.ToLowerInvariant(c).ToString())))
                .ToHashSet();
            Assert.Equal(tokens.OrderBy(x => x), names.OrderBy(x => x));
        }
    }

    [Fact]
    public void Codes_outside_the_catalog_and_without_problem_are_retry_backoff()
    {
        var actions = new ApiResult(AgentOperation.SubmitScan, 502, null, null, null, null, null).Actions;
        var unknown = new ApiResult(AgentOperation.SubmitScan, 418, null, "teapot", null, null, null).Actions;
        var portalOnly = new ApiResult(AgentOperation.CheckIn, 403, null, "forbidden", null, null, null).Actions;

        Assert.Equal(AgentActions.RetryBackoff, actions);
        Assert.Equal(AgentActions.RetryBackoff, unknown);
        Assert.Equal(AgentActions.RetryBackoff, portalOnly);
    }

    [Theory]
    [InlineData(AgentState.Unenrolled, "enrollment_key_invalid", AgentState.EnrollmentBlocked)]
    [InlineData(AgentState.Unenrolled, "organization_inactive", AgentState.Suspended)]
    [InlineData(AgentState.Unenrolled, "device_revoked", AgentState.Revoked)]
    [InlineData(AgentState.Unenrolled, "identity_conflict", AgentState.IdentityConflict)]
    [InlineData(AgentState.Unenrolled, "idempotency_conflict", AgentState.Unenrolled)]
    [InlineData(AgentState.Unenrolled, "challenge_invalid", AgentState.Unenrolled)]
    [InlineData(AgentState.Unenrolled, "rate_limited", AgentState.Backoff)]
    [InlineData(AgentState.Unenrolled, "temporarily_unavailable", AgentState.Backoff)]
    [InlineData(AgentState.EnrollmentBlocked, "enrollment_key_invalid", AgentState.EnrollmentBlocked)]
    [InlineData(AgentState.EnrollmentBlocked, "organization_inactive", AgentState.Suspended)]
    [InlineData(AgentState.EnrollmentBlocked, "rate_limited", AgentState.Backoff)]
    [InlineData(AgentState.Active, "device_unknown", AgentState.Unenrolled)]
    [InlineData(AgentState.Active, "device_revoked", AgentState.Revoked)]
    [InlineData(AgentState.Active, "organization_inactive", AgentState.Suspended)]
    [InlineData(AgentState.Active, "identity_conflict", AgentState.IdentityConflict)]
    [InlineData(AgentState.Active, "agent_version_unsupported", AgentState.VersionBlocked)]
    [InlineData(AgentState.Active, "unsupported_schema_version", AgentState.VersionBlocked)]
    [InlineData(AgentState.Active, "session_invalid", AgentState.Active)]
    [InlineData(AgentState.Active, "sequence_conflict", AgentState.Active)]
    [InlineData(AgentState.Active, "schema_violation", AgentState.Active)]
    [InlineData(AgentState.Active, "rate_limited", AgentState.Backoff)]
    [InlineData(AgentState.VersionBlocked, "device_unknown", AgentState.Unenrolled)]
    [InlineData(AgentState.VersionBlocked, "device_revoked", AgentState.Revoked)]
    [InlineData(AgentState.Suspended, "device_unknown", AgentState.Unenrolled)]
    [InlineData(AgentState.Suspended, "device_revoked", AgentState.Revoked)]
    [InlineData(AgentState.Suspended, "enrollment_key_invalid", AgentState.EnrollmentBlocked)]
    [InlineData(AgentState.IdentityConflict, "device_revoked", AgentState.Revoked)]
    [InlineData(AgentState.IdentityConflict, "device_unknown", AgentState.Unenrolled)]
    public void Rows_of_the_table_of_05(AgentState from, string code, AgentState expected)
    {
        var operation = code switch
        {
            "enrollment_key_invalid" or "idempotency_conflict" => AgentOperation.Enroll,
            "challenge_invalid" => AgentOperation.CreateChallenge,
            "device_unknown" => AgentOperation.CreateSession,
            "agent_version_unsupported" or "unsupported_schema_version" or "sequence_conflict" or "schema_violation" => AgentOperation.SubmitScan,
            _ => AgentOperation.CheckIn,
        };

        Assert.Equal(expected, After(from, code, operation, retryAfter: code == "temporarily_unavailable"));
    }

    [Fact]
    public void Backoff_returns_to_the_state_it_was_entered_from()
    {
        foreach (var origin in new[] { AgentState.Unenrolled, AgentState.EnrollmentBlocked, AgentState.Active })
        {
            var backoff = AgentStateMachine.OnFailure(AgentPosition.Of(origin), AgentActions.RetryBackoff, AgentOperation.CheckIn, null);
            Assert.Equal(AgentState.Backoff, backoff.State);
            Assert.Equal(origin, AgentStateMachine.On(backoff, AgentEvent.BackoffElapsed).State);
        }
    }

    [Theory]
    [InlineData(AgentState.Suspended, AgentEvent.CheckInSucceeded, AgentState.Active)]
    [InlineData(AgentState.IdentityConflict, AgentEvent.CheckInSucceeded, AgentState.Active)]
    [InlineData(AgentState.VersionBlocked, AgentEvent.TrialBatchAccepted, AgentState.Active)]
    [InlineData(AgentState.VersionBlocked, AgentEvent.AgentUpgraded, AgentState.Active)]
    [InlineData(AgentState.Unenrolled, AgentEvent.Enrolled, AgentState.Active)]
    [InlineData(AgentState.Suspended, AgentEvent.Enrolled, AgentState.Active)]
    [InlineData(AgentState.Unenrolled, AgentEvent.EnrollmentKeyMissing, AgentState.EnrollmentBlocked)]
    [InlineData(AgentState.EnrollmentBlocked, AgentEvent.EnrollmentKeyFileFound, AgentState.Unenrolled)]
    [InlineData(AgentState.Revoked, AgentEvent.Enrolled, AgentState.Revoked)]
    [InlineData(AgentState.Revoked, AgentEvent.AgentUpgraded, AgentState.Revoked)]
    [InlineData(AgentState.Active, AgentEvent.CheckInSucceeded, AgentState.Active)]
    public void Exits_of_the_table_of_05(AgentState from, AgentEvent ev, AgentState expected) =>
        Assert.Equal(expected, AgentStateMachine.On(From(from), ev).State);
}
