using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Sikkerheit.Contracts;
using Sikkerheit.ContractTests.Invariants;
using Sikkerheit.ContractTests.Support;
using Sikkerheit.Host.Operations;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.ContractTests;

/// <summary>
/// Records enforced by operations for the Windows agent: the replay of the security log after a point-in-time restore
/// (a copy of the database at T stands in for PITR). The RMM script (INV-201) belongs to the distribution of the agent.
/// </summary>
[Enforcement("infra")]
public sealed class AgentInfraInvariantTests(PostgresFixture postgres)
{
    private const string Oslo = ContractHost.Oslo;
    private readonly string _log = Path.Combine(Path.GetTempPath(), "sikkerheit-tests", Guid.NewGuid().ToString("N"), "log");
    private readonly string _files = Path.Combine(Path.GetTempPath(), "sikkerheit-tests", Guid.NewGuid().ToString("N"), "files");

    private static CancellationToken Ct => ContractHost.Ct;

    /// <summary>Builds the history on one database, copies it at T and lets «after» run on the original. Returns the copy and T.</summary>
    private async Task<(string Restored, DateTimeOffset T)> HistoryAsync(Func<ApiFactory, StaffClient, Task> before,
        Func<ApiFactory, StaffClient, Task> after)
    {
        var live = await postgres.CreateDatabaseAsync();
        DateTimeOffset t;
        await using (var factory = new ApiFactory(live, _log, _files))
        {
            factory.Clock.SetLocal(Oslo, 2026, 10, 1, 10);
            await before(factory, await StaffClient.SignInAsync(factory, "Admin"));
            factory.Clock.SetLocal(Oslo, 2026, 10, 10, 10);
            t = factory.Clock.GetUtcNow();
        }
        var restored = await postgres.CloneDatabaseAsync(live);
        await using (var factory = new ApiFactory(live, _log, _files))
        {
            factory.Clock.Set(t.AddHours(2));
            await after(factory, await StaffClient.SignInAsync(factory, "Admin"));
        }
        return (restored, t);
    }

    private static async Task<(Guid Org, string Key)> OrganizationWithKeyAsync(StaffClient admin)
    {
        var created = await admin.PostAsync("/api/v1/organizations", new { name = "Restaurant AS", timezone = Oslo, reportLanguage = "nb" }, "Organization");
        var org = Guid.Parse(created.Body.GetProperty("id").GetString()!);
        var key = await admin.PostAsync($"/api/v1/organizations/{org}/enrollment-keys", new { label = "RMM" }, "EnrollmentKey");
        return (org, key.Body.GetProperty("enrollmentKey").GetString()!);
    }

    private async Task<(ApiFactory Factory, RestoreReport Report)> RestoreAsync(string restored, DateTimeOffset since)
    {
        var factory = new ApiFactory(restored, _log, _files);
        factory.Clock.SetLocal(Oslo, 2026, 10, 20, 10);
        var report = await factory.Services.GetRequiredService<RestoreReplay>().RunAsync(new RestoreOptions(since, Drill: false), Ct);
        Assert.True(report.Verification.Passed, string.Join("; ", report.Verification.Problems));
        return (factory, report);
    }

    [Fact]
    [Invariant("INV-103")]
    public async Task Inv103_the_revocation_of_a_device_the_restored_database_lacks_still_blocks_its_installation()
    {
        Guid org = default;
        string key = "";
        var installation = Guid.NewGuid();
        // The device registers and is revoked after T while its agent is offline.
        var (restored, t) = await HistoryAsync(async (_, admin) => (org, key) = await OrganizationWithKeyAsync(admin), async (factory, admin) =>
        {
            using var agent = new FakeAgent(factory, key, installation);
            var device = await agent.EnrollOkAsync();
            var revoked = await admin.PostAsync($"/api/v1/organizations/{org}/devices/{device}/revoke", new { });
            Assert.Equal(HttpStatusCode.NoContent, revoked.Status);
        });

        var (factory, report) = await RestoreAsync(restored, t);
        await using (factory)
        {
            Assert.Contains(report.Records, r => r.Action == "device.revoke" && r.Outcome == "applied");
            using var agent = new FakeAgent(factory, key, installation);
            var reply = await agent.EnrollAsync();
            Assert.Equal((HttpStatusCode.Unauthorized, ProblemCodes.DeviceRevoked), (reply.Status, reply.Code));
            await using var scope = await factory.Services.GetRequiredService<Host.Data.DbScopes>().OrganizationAsync(org, Ct);
            var row = Assert.Single(scope.Db.RevokedInstallations.ToList());
            Assert.Equal(("restore_replay", installation), (row.Source, row.InstallationId));
            Assert.Empty(scope.Db.Devices.ToList());
        }
    }

    [Fact]
    [Invariant("INV-104")]
    public async Task Inv104_a_device_revoked_after_the_restore_point_stays_revoked_after_the_replay()
    {
        Guid org = default;
        string key = "";
        var installation = Guid.NewGuid();
        Guid device = default;
        var (restored, t) = await HistoryAsync(async (factory, admin) =>
        {
            (org, key) = await OrganizationWithKeyAsync(admin);
            using var agent = new FakeAgent(factory, key, installation);
            device = await agent.EnrollOkAsync();
        }, async (_, admin) =>
        {
            var revoked = await admin.PostAsync($"/api/v1/organizations/{org}/devices/{device}/revoke", new { });
            Assert.Equal(HttpStatusCode.NoContent, revoked.Status);
        });

        var (factory, report) = await RestoreAsync(restored, t);
        await using (factory)
        {
            Assert.Contains(report.Records, r => r.Action == "device.revoke" && r.Outcome == "applied");
            var admin = await StaffClient.SignInAsync(factory, "Admin");
            var devices = await admin.GetAsync($"/api/v1/organizations/{org}/devices", "DevicePage");
            Assert.Equal("revoked", devices.Body.GetProperty("items")[0].GetProperty("status").GetString());
            using var agent = new FakeAgent(factory, key, installation);
            var reply = await agent.EnrollAsync();
            Assert.Equal((HttpStatusCode.Unauthorized, ProblemCodes.DeviceRevoked), (reply.Status, reply.Code));
            // The replay is repeatable: the second run applies nothing new.
            var again = await factory.Services.GetRequiredService<RestoreReplay>().RunAsync(new RestoreOptions(t, Drill: false), Ct);
            Assert.All(again.Records.Where(r => r.Action == "device.revoke"), r => Assert.Equal("already_applied", r.Outcome));
        }
    }
}
