using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Sikkerheit.Contracts;
using Sikkerheit.ContractTests.Invariants;
using Sikkerheit.Host.Jobs;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.ContractTests;

/// <summary>Records enforced by the portal API of devices and of the release catalog (05 «API портала», FR-09, FR-10).</summary>
[Enforcement("portal_api")]
public sealed class AgentPortalInvariantTests(PostgresFixture postgres) : IAsyncLifetime
{
    private AgentHost _host = null!;

    public async ValueTask InitializeAsync() => _host = await AgentHost.StartAsync(postgres);

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    private static CancellationToken Ct => AgentHost.Ct;

    [Fact]
    [Invariant("INV-112")]
    public async Task Inv112_accepting_a_new_fingerprint_keeps_the_device_and_a_week_without_mismatches_clears_the_conflict()
    {
        var agent = await _host.EnrolledAsync();
        var deviceId = agent.DeviceId!.Value;
        Assert.Equal(HttpStatusCode.OK, (await agent.SubmitAsync(agent.Batch())).Status);

        // The motherboard was replaced: the machine fingerprint changed.
        var original = agent.Fingerprint;
        agent.Fingerprint = FakeAgent.ComputeFingerprint(agent.InstallationId, "4C4C4544-0042-3510-8058-B4C04F4E9999", "8C1F7A2E-3B4D-4E5F-9A6B-7C8D9E0F1A2B");
        var refused = await agent.CheckInAsync();
        Assert.Equal((HttpStatusCode.Conflict, ProblemCodes.IdentityConflict), (refused.Status, refused.Code));
        var device = await _host.DeviceAsync(deviceId);
        Assert.Equal(("identity_conflict", "fingerprint"), (device.IdentityState, device.ConflictKind));

        var resolved = await _host.Admin.PostAsync($"/api/v1/organizations/{_host.Org}/devices/{deviceId}/identity-resolutions",
            new { decision = "accept_new_fingerprint" }, "Device");
        Assert.Equal(HttpStatusCode.OK, resolved.Status);
        Assert.Equal(("ok", deviceId.ToString()), (resolved.Body.GetProperty("identityState").GetString(), resolved.Body.GetProperty("id").GetString()));
        Assert.Single(await _host.AuditAsync("device.identity_resolved"));
        Assert.Equal(HttpStatusCode.OK, (await agent.CheckInAsync()).Status);
        // The history of the device stays: the earlier batch and its assessments belong to the same deviceId.
        Assert.NotEmpty(await _host.AssessmentsAsync("WIN-002"));

        // Without a decision the conflict clears itself after 7 days without a mismatch.
        agent.Fingerprint = original;
        Assert.Equal(HttpStatusCode.Conflict, (await agent.CheckInAsync()).Status);
        Assert.Equal("identity_conflict", (await _host.DeviceAsync(deviceId)).IdentityState);
        _host.Clock.Set(_host.Clock.GetUtcNow().AddDays(8));
        await _host.Factory.Services.GetRequiredService<Scheduler>().RunOnceAsync(Ct);
        await _host.RunJobsAsync();
        Assert.Equal("ok", (await _host.DeviceAsync(deviceId)).IdentityState);
    }

    [Fact]
    [Invariant("INV-172")]
    public async Task Inv172_only_an_admin_imports_and_verifies_the_release_catalog()
    {
        var technician = await StaffClient.SignInAsync(_host.Factory, "Technician");
        var reader = await StaffClient.SignInAsync(_host.Factory, "Reader");
        foreach (var client in new[] { technician, reader })
        {
            var verify = await _host.VerifyMonthAsync("2026-10", noNewReleases: true, client);
            Assert.Equal((HttpStatusCode.Forbidden, ProblemCodes.Forbidden), (verify.Status, verify.Code));
            var import = await client.PostAsync("/api/v1/windows-releases/imports", new { source = "msrc_cvrf", securityMonth = "2026-10" });
            Assert.Equal((HttpStatusCode.Forbidden, ProblemCodes.Forbidden), (import.Status, import.Code));
        }
        // Technician and Reader read the catalog; the month stays unverified.
        Assert.Equal(HttpStatusCode.OK, (await technician.GetAsync("/api/v1/windows-releases", "WindowsReleasePage")).Status);
        Assert.Equal(HttpStatusCode.OK, (await _host.VerifyMonthAsync("2026-10", noNewReleases: true)).Status);
    }
}
