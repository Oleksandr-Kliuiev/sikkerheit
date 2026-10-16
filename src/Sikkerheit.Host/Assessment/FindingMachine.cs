using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.Assessment;

/// <summary>
/// Transitions of 05 «Таблица переходов finding». Every event pair is from the closed eventType × cause table;
/// repeats of the same input do not write a second event.
/// </summary>
public sealed class FindingMachine(SikkerheitDb db, Guid organizationId, DateTimeOffset now)
{
    /// <summary>Applies the current assessment of a pair. cause — source_change, rule_change or policy_change.</summary>
    public void Apply(Finding? finding, Data.Assessment assessment, string cause, bool notApplicableBySource)
    {
        var result = assessment.AssessmentMode == "informational" ? null : assessment.Result;
        if (result is null)
        {
            // The check became informational or inactive by policy: the open finding leaves the queue.
            if (finding is { TechnicalState: "open" })
            {
                Resolve(finding, "policy_changed", "policy_change", null);
            }
            return;
        }
        switch (result)
        {
            case "fail":
                if (finding is null)
                {
                    finding = new Finding
                    {
                        OrganizationId = organizationId, Id = Guid.CreateVersion7(), SubjectId = assessment.SubjectId,
                        CheckId = assessment.CheckId, TechnicalState = "open", WorkflowState = "new",
                        AssessmentResult = "fail", Severity = assessment.Severity!, Quality = "fresh_fail",
                        LatestAssessmentId = assessment.Id, LatestObservedAt = assessment.ObservedAt, OpenedAt = now,
                    };
                    db.Findings.Add(finding);
                    Event(finding, "opened", cause, assessment.Id);
                }
                else if (finding.TechnicalState == "open")
                {
                    if (finding.Quality != "fresh_fail")
                    {
                        Event(finding, "quality_changed", "data_quality", assessment.Id);
                    }
                    Touch(finding, assessment, "fresh_fail");
                    finding.Severity = assessment.Severity!;
                }
                else
                {
                    var decisionActive = finding.WorkflowState is "risk_accepted" or "suppressed" && finding.ReviewAt > now;
                    var from = finding.WorkflowState;
                    finding.TechnicalState = "open";
                    finding.ResolvedAt = null;
                    finding.Severity = assessment.Severity!;
                    if (!decisionActive)
                    {
                        finding.WorkflowState = "new";
                    }
                    Touch(finding, assessment, "fresh_fail");
                    Event(finding, "reopened", cause, assessment.Id, from, finding.WorkflowState);
                }
                break;
            case "pass":
                if (finding is { TechnicalState: "open" })
                {
                    finding.AssessmentResult = "pass";
                    Resolve(finding, "resolved", cause, assessment.Id);
                    finding.LatestAssessmentId = assessment.Id;
                    finding.LatestObservedAt = assessment.ObservedAt;
                }
                break;
            case "unknown":
                if (finding is { TechnicalState: "open" })
                {
                    if (finding.Quality != "unknown")
                    {
                        Event(finding, "quality_changed", "data_quality", assessment.Id);
                    }
                    Touch(finding, assessment, "unknown");
                }
                break;
            case "not_applicable":
                if (finding is { TechnicalState: "open" })
                {
                    finding.AssessmentResult = "not_applicable";
                    if (notApplicableBySource)
                    {
                        Resolve(finding, "resolved", "applicability_change", assessment.Id);
                    }
                    else
                    {
                        Resolve(finding, "policy_changed", "policy_change", assessment.Id);
                    }
                    finding.LatestAssessmentId = assessment.Id;
                }
                break;
        }
    }

    /// <summary>The subject left the source (cause source_change) or was revoked (manual_action).</summary>
    public void Retire(Finding finding, string cause, Guid? actorId = null)
    {
        if (finding.TechnicalState == "open")
        {
            Resolve(finding, "subject_retired", cause, null, actorId);
        }
    }

    /// <summary>The check left activeCheckIds of the new revision: the open finding leaves the queue (policy_changed).</summary>
    public void PolicyRemoved(Finding finding)
    {
        if (finding.TechnicalState == "open")
        {
            Resolve(finding, "policy_changed", "policy_change", null);
        }
    }

    /// <summary>Freshness changed without a new assessment (freshness_sweep): fresh_fail ↔ stale.</summary>
    public void Quality(Finding finding, string quality)
    {
        if (finding.TechnicalState == "open" && finding.Quality != quality)
        {
            finding.Quality = quality;
            finding.Revision++;
            Event(finding, "quality_changed", "data_quality", null);
        }
    }

    private void Touch(Finding finding, Data.Assessment assessment, string quality)
    {
        finding.AssessmentResult = assessment.Result!;
        finding.Quality = quality;
        finding.LatestAssessmentId = assessment.Id;
        finding.LatestObservedAt = assessment.ObservedAt;
        finding.Revision++;
    }

    private void Resolve(Finding finding, string eventType, string cause, Guid? assessmentId, Guid? actorId = null)
    {
        finding.TechnicalState = "resolved";
        finding.ResolvedAt = now;
        finding.Revision++;
        Event(finding, eventType, cause, assessmentId, actorId: actorId);
    }

    private void Event(Finding finding, string eventType, string cause, Guid? assessmentId, string? from = null,
        string? to = null, Guid? actorId = null)
    {
        if (from == to)
        {
            from = null;
            to = null;
        }
        db.FindingEvents.Add(new FindingEvent
        {
            OrganizationId = organizationId, FindingId = finding.Id, Id = Guid.CreateVersion7(), EventType = eventType,
            Cause = cause, AssessmentId = assessmentId, ActorId = actorId, FromWorkflowState = from, ToWorkflowState = to,
            OccurredAt = now,
        });
    }
}
