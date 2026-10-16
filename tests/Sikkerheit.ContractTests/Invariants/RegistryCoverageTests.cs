using System.Reflection;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.ContractTests.Invariants;

/// <summary>
/// WP-01, WP-10: every record of the registry has an automatic negative test on its enforcement, and a record without a
/// test fails the build. The server side of P2 (agent API, evaluator, jobs, portal, schema, operations) is tested too;
/// the records that only the Windows agent or its distribution can enforce are reported as skipped with the reason.
/// </summary>
public sealed class RegistryCoverageTests
{
    /// <summary>Layers that need the service or its database: their test classes run against PostgreSQL.</summary>
    private static readonly string[] ServerLevels = ["portal_api", "db_rls", "collector", "worker", "infra", "agent_api"];

    private sealed record Covered(string Id, string Level, MethodInfo Test);

    private static IReadOnlyList<Covered> Tests() =>
        typeof(RegistryCoverageTests).Assembly.GetTypes()
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .Where(m => m.GetCustomAttribute<FactAttribute>() is not null)
                .SelectMany(m => m.GetCustomAttributes<InvariantAttribute>().Select(a => new Covered(a.Id,
                    type.GetCustomAttribute<EnforcementAttribute>()?.Level ?? "(no [Enforcement] on " + type.Name + ")", m))))
            .ToList();

    /// <summary>Enforcement that only code on the Windows PC has (WP-09); the script of the RMM (INV-201) belongs to WP-11.</summary>
    private static readonly string[] AgentOnly = ["agent"];

    private static bool WaitsForAgent(InvariantRecord record) => record.Enforcement == "agent" || record.Id == "INV-201";

    [Fact]
    public void Registry_is_the_one_of_the_package_and_has_records_of_both_stages()
    {
        Assert.True(File.Exists(InvariantRegistry.RegistryPath), InvariantRegistry.RegistryPath);
        Assert.NotEmpty(InvariantRegistry.P1);
        Assert.NotEmpty(InvariantRegistry.P2);
        Assert.Equal(InvariantRegistry.All.Count, InvariantRegistry.All.Select(r => r.Id).Distinct().Count());
    }

    [Fact]
    public void Every_P1_record_has_a_negative_test_on_its_enforcement()
    {
        var tests = Tests();
        var iac = InvariantRegistry.IacInvariants();
        var missing = InvariantRegistry.P1
            .Where(r => !tests.Any(t => t.Id == r.Id && t.Level == r.Enforcement) && !(r.Enforcement == "infra" && iac.Contains(r.Id)))
            .Select(r => $"{r.Id} [{r.Enforcement}] {r.NegativeExample} → {r.ExpectedError}")
            .ToList();
        Assert.True(missing.Count == 0, "Records without a negative test on their enforcement:\n" + string.Join("\n", missing));
    }

    [Fact]
    public void Every_P2_record_of_the_server_has_a_negative_test_on_its_enforcement()
    {
        var tests = Tests();
        var missing = InvariantRegistry.P2
            .Where(r => !WaitsForAgent(r) && !tests.Any(t => t.Id == r.Id && t.Level == r.Enforcement))
            .Select(r => $"{r.Id} [{r.Enforcement}] {r.NegativeExample} → {r.ExpectedError}")
            .ToList();
        Assert.True(missing.Count == 0, "Records of the server without a negative test on their enforcement:\n" + string.Join("\n", missing));
    }

    [Fact]
    public void Every_invariant_test_names_a_record_of_its_class_enforcement()
    {
        var wrong = new List<string>();
        foreach (var test in Tests())
        {
            var record = InvariantRegistry.Find(test.Id);
            if (record is null)
            {
                wrong.Add($"{test.Test.DeclaringType!.Name}.{test.Test.Name}: {test.Id} is not in the registry");
            }
            else if (record.Phase == "P2" && AgentOnly.Contains(record.Enforcement) || record.Id is "INV-201")
            {
                wrong.Add($"{test.Test.DeclaringType!.Name}.{test.Test.Name}: {test.Id} is enforced by the agent or its distribution");
            }
            else if (record.Enforcement != test.Level)
            {
                wrong.Add($"{test.Test.DeclaringType!.Name}.{test.Test.Name}: {test.Id} is enforced by {record.Enforcement}, not {test.Level}");
            }
        }
        Assert.True(wrong.Count == 0, string.Join("\n", wrong));
    }

    [Fact]
    public void Infra_records_declared_by_the_IaC_check_exist()
    {
        var iac = InvariantRegistry.IacInvariants();
        Assert.True(iac.Count > 0, "tools/iac/check_arm.py declares no INVARIANTS tuple");
        Assert.All(iac, id => Assert.Equal("infra", InvariantRegistry.Find(id)?.Enforcement));
    }

    [Fact]
    public void Test_classes_of_server_layers_run_against_PostgreSQL()
    {
        var classes = typeof(RegistryCoverageTests).Assembly.GetTypes()
            .Where(t => t.GetCustomAttribute<EnforcementAttribute>() is { } e && ServerLevels.Contains(e.Level));
        Assert.All(classes, type => Assert.Contains(type.GetConstructors().SelectMany(c => c.GetParameters()),
            p => p.ParameterType == typeof(PostgresFixture)));
    }

    public static TheoryData<string> WaitingRecords => new(InvariantRegistry.P2.Where(WaitsForAgent).Select(r => r.Id));

    [Theory]
    [MemberData(nameof(WaitingRecords))]
    public void P2_record_waits_for_the_Windows_agent(string id)
    {
        var record = InvariantRegistry.Find(id)!;
        Assert.Skip($"{id} [{record.Enforcement}], {record.Acceptance}: enforced on the Windows PC by the agent (WP-09) or by the RMM "
                    + "script that installs it (WP-11); the server side of the record is not what it checks");
    }
}
