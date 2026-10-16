using System.Reflection;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.ContractTests.Invariants;

/// <summary>
/// WP-01: every record of the registry has an automatic negative test on its enforcement, and a record without a test
/// fails the build. Records of stage P2 (the Windows agent) are reported as skipped with the reason, not left out.
/// </summary>
public sealed class RegistryCoverageTests
{
    /// <summary>Layers that need the service or its database: their test classes run against PostgreSQL.</summary>
    private static readonly string[] ServerLevels = ["portal_api", "db_rls", "collector", "worker", "infra"];

    private sealed record Covered(string Id, string Level, MethodInfo Test);

    private static IReadOnlyList<Covered> Tests() =>
        typeof(RegistryCoverageTests).Assembly.GetTypes()
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .Where(m => m.GetCustomAttribute<FactAttribute>() is not null)
                .SelectMany(m => m.GetCustomAttributes<InvariantAttribute>().Select(a => new Covered(a.Id,
                    type.GetCustomAttribute<EnforcementAttribute>()?.Level ?? "(no [Enforcement] on " + type.Name + ")", m))))
            .ToList();

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
    public void Every_invariant_test_names_a_P1_record_of_its_class_enforcement()
    {
        var wrong = new List<string>();
        foreach (var test in Tests())
        {
            var record = InvariantRegistry.Find(test.Id);
            if (record is null)
            {
                wrong.Add($"{test.Test.DeclaringType!.Name}.{test.Test.Name}: {test.Id} is not in the registry");
            }
            else if (record.Phase != "P1")
            {
                wrong.Add($"{test.Test.DeclaringType!.Name}.{test.Test.Name}: {test.Id} is a {record.Phase} record");
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

    public static TheoryData<string> P2Records => new(InvariantRegistry.P2.Select(r => r.Id));

    [Theory]
    [MemberData(nameof(P2Records))]
    public void P2_record_waits_for_the_Windows_agent(string id)
    {
        var record = InvariantRegistry.Find(id)!;
        Assert.Skip($"{id} [{record.Enforcement}], {record.Acceptance}: stage P2 — the Windows agent, the agent API and the device "
                    + "rules (WP-09…WP-12) are not built yet; the negative test comes with them");
    }
}
