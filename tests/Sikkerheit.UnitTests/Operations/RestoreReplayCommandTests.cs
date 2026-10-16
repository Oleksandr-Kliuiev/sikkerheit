using Sikkerheit.Host.Operations;
using Sikkerheit.Host.Organizations;
using Sikkerheit.Host.Reports;

namespace Sikkerheit.UnitTests.Operations;

/// <summary>RB-05: arguments of the maintenance command and the pure parts of the restore steps.</summary>
public sealed class RestoreReplayCommandTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 10, 9, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Arguments_need_a_point_in_time_with_an_offset()
    {
        var parsed = RestoreReplayCommand.Parse(["--since", "2026-10-21T10:00:00+02:00", "--drill", "--report", "/home/LogFiles/r.json"],
            Now, out var error);
        Assert.Null(error);
        Assert.Equal(new DateTimeOffset(2026, 10, 21, 8, 0, 0, TimeSpan.Zero), parsed!.Options.Since);
        Assert.Equal(TimeSpan.Zero, parsed.Options.Since.Offset);
        Assert.True(parsed.Options.Drill);
        Assert.Equal("/home/LogFiles/r.json", parsed.ReportPath);
        Assert.False(RestoreReplayCommand.Parse(["--since", "2026-10-21T08:00:00Z"], Now, out _)!.Options.Drill);
    }

    [Theory]
    [InlineData(new string[0], "--since is required")]
    [InlineData(new[] { "--since", "2026-10-21T10:00:00" }, "--since must be")]
    [InlineData(new[] { "--since", "yesterday" }, "--since must be")]
    [InlineData(new[] { "--since", "2026-12-01T00:00:00Z" }, "--since lies in the future")]
    [InlineData(new[] { "--since", "2026-10-21T08:00:00Z", "--since", "2026-10-22T08:00:00Z" }, "unexpected argument")]
    [InlineData(new[] { "--since", "2026-10-21T08:00:00Z", "--sql", "delete from job" }, "unexpected argument '--sql'")]
    [InlineData(new[] { "--report" }, "unexpected argument '--report'")]
    public void Wrong_arguments_are_refused(string[] args, string message)
    {
        Assert.Null(RestoreReplayCommand.Parse(args, Now, out var error));
        Assert.StartsWith(message, error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0, 10_000)]
    [InlineData(1, 10_000)]
    [InlineData(9_999, 10_000)]
    [InlineData(10_000, 20_000)]
    [InlineData(10_143, 20_000)]
    public void Policy_versions_continue_from_the_next_epoch(int maxVersion, int next) =>
        Assert.Equal(next, OrganizationLifecycle.NextEpoch(maxVersion));

    [Fact]
    public void Epoch_after_an_earlier_restore_skips_the_versions_that_may_be_lost()
    {
        // The restored organization already continued from epoch 10000; revisions 10000… after T may be lost.
        var organization = new Sikkerheit.Host.Data.Organization { NextPolicyVersion = 10_000 };
        Assert.Equal(20_000, OrganizationLifecycle.AdvancePolicyEpoch(organization, maxVersion: 7));
        var fresh = new Sikkerheit.Host.Data.Organization { NextPolicyVersion = 8 };
        Assert.Equal(10_000, OrganizationLifecycle.AdvancePolicyEpoch(fresh, maxVersion: 7));
    }

    [Fact]
    public void Digest_periods_after_the_restore_point_follow_the_oslo_sending_time()
    {
        // 07:30 Oslo on 21 October (05:30 UTC) is before T, on 25 October summer time ends.
        var periods = TeamsDigestJob.PeriodsBetween(new DateTimeOffset(2026, 10, 21, 8, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 10, 26, 6, 30, 0, TimeSpan.Zero));
        Assert.Equal(["2026-10-22", "2026-10-23", "2026-10-24", "2026-10-25", "2026-10-26"], periods);
        Assert.Empty(TeamsDigestJob.PeriodsBetween(new DateTimeOffset(2026, 10, 26, 6, 31, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 10, 27, 6, 29, 0, TimeSpan.Zero)));
    }

    [Fact]
    public void Report_file_names_carry_the_week_for_the_restore()
    {
        var org = Guid.NewGuid();
        var report = Guid.NewGuid();
        var key = ReportService.FileKey(org, "2026-W42", report);
        Assert.Equal($"{org}/2026-W42/{report}.html", key);
        Assert.True(ReportService.TryParseFileKey(key, out var parsedOrg, out var period));
        Assert.Equal((org, "2026-W42"), (parsedOrg, period));
        Assert.False(ReportService.TryParseFileKey($"{org}/{report}.html", out _, out _));
        Assert.False(ReportService.TryParseFileKey($"{org}/2026-W54/{report}.html", out _, out _));
        Assert.False(ReportService.TryParseFileKey($"{org}/2026-W42/{report}.zip", out _, out _));
    }
}
