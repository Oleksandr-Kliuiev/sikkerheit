namespace Sikkerheit.Contracts;

/// <summary>Check of the catalog (03): id, name, phase, default mode, data source and subject type.</summary>
public sealed record CheckDefinition(string CheckId, string Name, string Phase, string DefaultMode, string Source, string SubjectType);

/// <summary>Allowed causes of a finding event and whether assessmentId is required, nullable or null.</summary>
public sealed record EventRule(IReadOnlyList<string> Causes, string Assessment);

/// <summary>Problem.code with its HTTP status and the agent action from the 05 table.</summary>
public sealed record ProblemDefinition(string Code, int Status, string AgentAction);

public static partial class Catalog
{
    private static readonly Dictionary<string, CheckDefinition> ChecksById = Checks.ToDictionary(c => c.CheckId, StringComparer.Ordinal);

    public static CheckDefinition Check(string checkId) =>
        ChecksById.TryGetValue(checkId, out var check) ? check : throw new KeyNotFoundException($"Unknown check {checkId}");

    public static IEnumerable<CheckDefinition> ChecksOfPhase(string phase) => Checks.Where(c => c.Phase == phase);

    public static int StatusOf(string problemCode) =>
        Problems.TryGetValue(problemCode, out var problem) ? problem.Status : throw new KeyNotFoundException(problemCode);
}
