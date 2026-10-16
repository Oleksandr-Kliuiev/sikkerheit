using System.Text.RegularExpressions;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Assessment;

namespace Sikkerheit.UnitTests.Assessment;

/// <summary>The texts of the Windows and server rules exist in nb, nn and en for every check and every outcome key (01).</summary>
public sealed partial class WindowsTextsTests
{
    private static readonly string[] Sources = ["WindowsRules.cs", "ServerRules.cs", "ServerChecks.cs"];

    [GeneratedRegex("\"((?:win|sys)[-.][a-z0-9._-]*)\"")]
    private static partial Regex ExplanationKey();

    [Fact]
    public void Every_check_of_P2_has_a_title_and_a_recommendation_in_every_language()
    {
        foreach (var check in Catalog.ChecksOfPhase("P2"))
        {
            foreach (var language in Texts.Languages)
            {
                Assert.True(Texts.HasCheckTexts(check.CheckId, language), check.CheckId + " " + language);
            }
        }
    }

    [Fact]
    public void Every_explanation_key_of_the_rules_has_a_text_in_every_language()
    {
        var keys = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var source in Sources)
        {
            var text = File.ReadAllText(Path.Combine(RepoPaths.Root, "src", "Sikkerheit.Host", "Assessment", source));
            foreach (Match match in ExplanationKey().Matches(text))
            {
                keys.Add(match.Groups[1].Value);
            }
        }
        // Keys built from a reason or a severity.
        foreach (var reason in Catalog.AgentCollectorReasons)
        {
            keys.Add("win.unavailable." + reason);
        }
        keys.Add("sys-003.fail.warning");
        keys.Add("sys-003.fail.critical");
        keys.Remove("sys-003.fail.");
        keys.Remove("win.unavailable.");
        var missing = keys.Where(k => !Texts.HasAllLanguages(k)).ToList();
        Assert.True(missing.Count == 0, "No text for: " + string.Join(", ", missing));
        Assert.True(keys.Count > 40);
    }

    [Fact]
    public void Placeholders_of_a_text_are_the_same_in_every_language()
    {
        foreach (var key in Texts.ExplanationKeys)
        {
            var sets = Texts.Languages.Select(language => Texts.Explanation($$"""{"explanation":"{{key}}"}""", language))
                .Select(text => Regex.Matches(text, @"\{[a-zA-Z]+\}").Select(m => m.Value).Order().ToList()).ToList();
            Assert.True(sets.All(set => set.SequenceEqual(sets[0])), key);
        }
    }

    [Fact]
    public void Patch_tuesday_is_the_second_tuesday_and_the_expected_month_follows_the_grace_period()
    {
        Assert.Equal(new DateTime(2026, 10, 13), ServerRules.SecondTuesday(2026, 10).Date);
        Assert.Equal(new DateTime(2026, 1, 13), ServerRules.SecondTuesday(2026, 1).Date);
        Assert.Equal("2026-09", ServerRules.ExpectedMonth(new DateTimeOffset(2026, 10, 26, 0, 0, 0, TimeSpan.Zero), 14));
        Assert.Equal("2026-10", ServerRules.ExpectedMonth(new DateTimeOffset(2026, 10, 27, 0, 0, 0, TimeSpan.Zero), 14));
        Assert.Equal("2026-10", ServerRules.ExpectedMonth(new DateTimeOffset(2026, 10, 13, 0, 0, 0, TimeSpan.Zero), 0));
        Assert.Equal("2025-12", ServerRules.ExpectedMonth(new DateTimeOffset(2026, 1, 20, 0, 0, 0, TimeSpan.Zero), 14));
    }

    [Fact]
    public void The_verified_chain_of_months_is_broken_by_the_first_month_that_is_not_verified()
    {
        Assert.Null(ReleaseCatalogStore.VerifiedThrough([]));
        Assert.Equal("2026-09", ReleaseCatalogStore.VerifiedThrough([("2026-08", true), ("2026-09", true), ("2026-10", false)]));
        Assert.Null(ReleaseCatalogStore.VerifiedThrough([("2026-08", false), ("2026-09", true)]));
        Assert.Equal("2026-08", ReleaseCatalogStore.VerifiedThrough([("2026-08", true), ("2026-10", true)]));
    }

    [Fact]
    public void The_lifecycle_table_is_the_one_of_the_package()
    {
        // 03 «Жизненный цикл ОС»: 22 rows, each end an exclusive start of the next day in Los Angeles (07:00 or 08:00 UTC).
        Assert.Equal(22, ServerRules.Lifecycle.Count);
        Assert.All(ServerRules.Lifecycle, row => Assert.Contains(row.ServicingEndsAt.Hour, new[] { 7, 8 }));
        var doc = File.ReadAllText(Path.Combine(RepoPaths.Root, "development-package", "03-check-catalog.md"));
        foreach (var row in ServerRules.Lifecycle)
        {
            Assert.Contains(row.ServicingEndsAt.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"), doc);
        }
    }
}
