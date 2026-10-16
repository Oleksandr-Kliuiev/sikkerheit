using System.Text.Json;
using System.Text.RegularExpressions;

namespace Sikkerheit.ContractTests.Invariants;

/// <summary>A record of development-package/specs/invariants.json.</summary>
public sealed record InvariantRecord(string Id, string Phase, string Enforcement, string Rule, string NegativeExample,
    string ExpectedError, string Acceptance);

/// <summary>The registry of invariants outside JSON Schema: every P1 record gets a negative test on its enforcement (WP-01).</summary>
public static partial class InvariantRegistry
{
    public static string Root { get; } = FindRoot();

    public static string RegistryPath => Path.Combine(Root, "development-package", "specs", "invariants.json");

    /// <summary>The IaC check of the compiled Bicep; its INVARIANTS tuple names the infra records it checks.</summary>
    public static string IacCheckPath => Path.Combine(Root, "tools", "iac", "check_arm.py");

    public static IReadOnlyList<InvariantRecord> All { get; } = Load();

    public static IReadOnlyList<InvariantRecord> P1 { get; } = All.Where(r => r.Phase == "P1").ToList();

    public static IReadOnlyList<InvariantRecord> P2 { get; } = All.Where(r => r.Phase == "P2").ToList();

    public static InvariantRecord? Find(string id) => All.FirstOrDefault(r => r.Id == id);

    /// <summary>Records the IaC script declares it checks (one line: INVARIANTS = ("INV-…", …)).</summary>
    public static IReadOnlyList<string> IacInvariants()
    {
        if (!File.Exists(IacCheckPath))
        {
            return [];
        }
        var match = IacTuple().Match(File.ReadAllText(IacCheckPath));
        return match.Success ? InvariantId().Matches(match.Groups[1].Value).Select(m => m.Value).ToList() : [];
    }

    private static List<InvariantRecord> Load()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(RegistryPath));
        return document.RootElement.GetProperty("invariants").EnumerateArray().Select(r => new InvariantRecord(
            r.GetProperty("id").GetString()!, r.GetProperty("phase").GetString()!, r.GetProperty("enforcement").GetString()!,
            r.GetProperty("rule").GetString()!, r.GetProperty("negativeExample").GetString()!,
            r.GetProperty("expectedError").GetRawText(), r.GetProperty("acceptance").GetString()!)).ToList();
    }

    private static string FindRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Sikkerheit.slnx")))
        {
            directory = directory.Parent;
        }
        return directory?.FullName ?? throw new InvalidOperationException("Repository root not found");
    }

    [GeneratedRegex(@"^INVARIANTS\s*=\s*\(([^)]*)\)", RegexOptions.Multiline)]
    private static partial Regex IacTuple();

    [GeneratedRegex(@"INV-\d{3}")]
    private static partial Regex InvariantId();
}

/// <summary>The test reproduces the negative example of a registry record and expects its error.</summary>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
public sealed class InvariantAttribute(string id) : Attribute
{
    public string Id { get; } = id;

    /// <summary>A recorded decision that changed the record after this version of the package (docs/reviews).</summary>
    public string? Decision { get; init; }
}

/// <summary>The layer where the tests of the class enforce their records: the enforcement of invariants.json.</summary>
[AttributeUsage(AttributeTargets.Class)]
public sealed class EnforcementAttribute(string level) : Attribute
{
    public string Level { get; } = level;
}
