using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
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

    private static IConfiguration Settings(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values.ToDictionary(v => v.Key, v => (string?)v.Value)).Build();

    private static readonly (string, string) LogContainer = ("SecurityLog:ContainerUri", "https://stexample.blob.core.windows.net/security-log");
    private static readonly (string, string) Account = ("Storage:BlobServiceUri", "https://stexample.blob.core.windows.net/");

    [Fact]
    public void In_azure_the_journal_is_read_with_the_restore_identity_and_a_drill_reads_the_files_with_it_too()
    {
        var directory = Path.Combine(Path.GetTempPath(), "sikkerheit-tests", Guid.NewGuid().ToString("N"));
        var log = new FileSecurityLog(Path.Combine(directory, "log"));
        var files = new LocalFileStore(Path.Combine(directory, "files"));
        using var services = new ServiceCollection().AddSingleton<ISecurityLog>(log).AddSingleton<IFileStore>(files)
            .BuildServiceProvider();

        // Development and tests: the local stores of the service.
        var local = RestoreReplayCommand.StoresOf(services, Settings(), drill: true, out var none);
        Assert.Null(none);
        Assert.Same(log, local!.SecurityLog);
        Assert.Same(files, local.Files);

        Assert.Null(RestoreReplayCommand.StoresOf(services, Settings(LogContainer, Account), drill: false, out var refusal));
        Assert.StartsWith("Restore__ManagedIdentityClientId is not set", refusal, StringComparison.Ordinal);

        var azure = Settings(LogContainer, Account, (RestoreReplayCommand.IdentitySetting, "77777777-7777-7777-7777-777777777777"));
        var restore = RestoreReplayCommand.StoresOf(services, azure, drill: false, out _)!;
        Assert.IsType<BlobSecurityLog>(restore.SecurityLog);
        // A real restore moves files to quarantine: they stay with the store of the service and its slot identity.
        Assert.Same(files, restore.Files);
        var drill = RestoreReplayCommand.StoresOf(services, azure, drill: true, out _)!;
        Assert.IsType<BlobSecurityLog>(drill.SecurityLog);
        Assert.IsType<BlobFileStore>(drill.Files);
    }

    [Fact]
    public async Task The_command_refuses_azure_without_the_restore_identity()
    {
        var configuration = Settings(("Jobs:Enabled", "false"), LogContainer, Account);
        await using var services = new ServiceCollection().AddSingleton(configuration).AddSingleton(TimeProvider.System)
            .AddLogging().BuildServiceProvider();
        var errors = new StringWriter();
        Assert.Equal(2, await RestoreReplayCommand.RunAsync(services, ["--since", "2026-10-01T08:00:00Z"], TextWriter.Null,
            errors, TestContext.Current.CancellationToken));
        Assert.Contains("Restore__ManagedIdentityClientId is not set", errors.ToString(), StringComparison.Ordinal);
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
