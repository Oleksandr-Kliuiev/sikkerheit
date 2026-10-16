using Sikkerheit.Agent.Api;

namespace Sikkerheit.Agent.Runtime;

/// <summary>States of the agent (05, "Конечный автомат агента").</summary>
public enum AgentState
{
    Unenrolled,
    EnrollmentBlocked,
    Active,
    Backoff,
    VersionBlocked,
    Suspended,
    Revoked,
    IdentityConflict,
}

/// <summary>State with the state to which Backoff returns after the pause.</summary>
public readonly record struct AgentPosition(AgentState State, AgentState? BackoffReturn = null)
{
    public static AgentPosition Of(AgentState state) => new(state);
}

/// <summary>Events outside the table of errors that move the automaton.</summary>
public enum AgentEvent
{
    /// <summary>201 on registration.</summary>
    Enrolled,

    /// <summary>Successful check-in (in Suspended and IdentityConflict).</summary>
    CheckInSucceeded,

    /// <summary>The trial batch in VersionBlocked was accepted.</summary>
    TrialBatchAccepted,

    /// <summary>A new version of the agent was installed by RMM.</summary>
    AgentUpgraded,

    /// <summary>The pause of Backoff is over.</summary>
    BackoffElapsed,

    /// <summary>The registration key is absent: nothing to register with.</summary>
    EnrollmentKeyMissing,

    /// <summary>A new registration key file appeared.</summary>
    EnrollmentKeyFileFound,
}

/// <summary>
/// The table of 05 as a function. A pure model without time and I/O: a model test goes through every state and every code of the
/// catalog. The actions without a state change (drop_batch, refresh_configuration, resync_sequence, renew_session, new_challenge,
/// skip_request, reenroll with a new registrationRequestId) are carried out by the caller.
/// </summary>
public static class AgentStateMachine
{
    public static AgentPosition OnFailure(AgentPosition from, AgentActions actions, AgentOperation operation, string? problemCode)
    {
        var state = from.State;
        if (state == AgentState.Revoked)
        {
            return from;
        }
        // device_revoked ends the installation from any state; device_unknown leads to Unenrolled from any state but Revoked.
        if (actions.HasFlag(AgentActions.StopUntilReinstall))
        {
            return AgentPosition.Of(AgentState.Revoked);
        }
        if (problemCode == "device_unknown")
        {
            return AgentPosition.Of(AgentState.Unenrolled);
        }
        if (actions.HasFlag(AgentActions.IdentityStop))
        {
            return AgentPosition.Of(AgentState.IdentityConflict);
        }
        if (actions.HasFlag(AgentActions.StopUntilUpgrade))
        {
            return AgentPosition.Of(AgentState.VersionBlocked);
        }
        if (actions.HasFlag(AgentActions.SuspendUntilActive))
        {
            return AgentPosition.Of(AgentState.Suspended);
        }
        if (actions.HasFlag(AgentActions.AwaitEnrollmentKey))
        {
            return AgentPosition.Of(AgentState.EnrollmentBlocked);
        }
        if (actions.HasFlag(AgentActions.RetryAfter) || actions.HasFlag(AgentActions.RetryBackoff))
        {
            // Backoff is entered from Unenrolled, EnrollmentBlocked and Active; the other states retry on their own schedule.
            return state is AgentState.Unenrolled or AgentState.EnrollmentBlocked or AgentState.Active
                ? new AgentPosition(AgentState.Backoff, state)
                : from;
        }
        return from;
    }

    public static AgentPosition On(AgentPosition from, AgentEvent ev)
    {
        var state = from.State;
        if (state == AgentState.Revoked)
        {
            return from;
        }
        return ev switch
        {
            AgentEvent.Enrolled => AgentPosition.Of(AgentState.Active),
            AgentEvent.CheckInSucceeded when state is AgentState.Suspended or AgentState.IdentityConflict => AgentPosition.Of(AgentState.Active),
            AgentEvent.TrialBatchAccepted when state == AgentState.VersionBlocked => AgentPosition.Of(AgentState.Active),
            AgentEvent.AgentUpgraded when state == AgentState.VersionBlocked => AgentPosition.Of(AgentState.Active),
            AgentEvent.BackoffElapsed when state == AgentState.Backoff => AgentPosition.Of(from.BackoffReturn ?? AgentState.Active),
            AgentEvent.EnrollmentKeyMissing when state == AgentState.Unenrolled => AgentPosition.Of(AgentState.EnrollmentBlocked),
            AgentEvent.EnrollmentKeyFileFound when state == AgentState.EnrollmentBlocked => AgentPosition.Of(AgentState.Unenrolled),
            _ => from,
        };
    }
}
