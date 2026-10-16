using System.Net;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Sikkerheit.Contracts;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.IntegrationTests;

/// <summary>FR-09, FR-10: registration, session, check-in and the intake of batches over HTTP (AT-12, AT-13).</summary>
public sealed class AgentApiTests(PostgresFixture postgres) : IAsyncLifetime
{
    private AgentHost _host = null!;

    public async ValueTask InitializeAsync() => _host = await AgentHost.StartAsync(postgres);

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public void The_fingerprint_matches_the_test_vector_of_the_package()
    {
        Assert.Equal("150364374d6891dc5194327d8c0500ed000a876f0d7da212e8f1b67ae6a39bd9",
            FakeAgent.ComputeFingerprint(Guid.Parse("6f1c2d3e-4a5b-4c6d-8e7f-9a0b1c2d3e4f"), "4C4C4544-0042-3510-8058-B4C04F4E3732",
                "{8C1F7A2E-3B4D-4E5F-9A6B-7C8D9E0F1A2B}"));
    }

    [Fact]
    public async Task An_agent_registers_gets_a_session_checks_in_and_sends_a_batch()
    {
        using var agent = _host.NewAgent();
        var deviceId = await agent.EnrollOkAsync();
        var device = await _host.DeviceAsync(deviceId);
        Assert.Equal(("active", "PC-ANNE", "software"), (device.Status, device.DisplayName, device.KeyProtection));
        Assert.Single(await _host.SubjectsAsync("device"));
        Assert.Single(await _host.AuditAsync("device.enroll"));

        await agent.StartSessionAsync();
        var config = await agent.CheckInAsync();
        Assert.Equal(HttpStatusCode.OK, config.Status);
        Assert.Equal(1, config.Body.GetProperty("policyVersion").GetInt32());
        Assert.Equal(11, config.Body.GetProperty("activeCheckIds").GetArrayLength());
        Assert.Equal(0, config.Body.GetProperty("lastAcceptedSequence").GetInt64());
        Assert.Equal(262144, config.Body.GetProperty("maxBatchBytes").GetInt32());

        var receipt = await agent.SubmitAsync(agent.Batch());
        Assert.Equal(HttpStatusCode.OK, receipt.Status);
        Assert.False(receipt.Body.GetProperty("duplicate").GetBoolean());
        Assert.False(receipt.Body.GetProperty("clockInconsistent").GetBoolean());
        Assert.Equal(1, (await _host.DeviceAsync(deviceId)).LastAcceptedSequence);
        // Every required pair has a current assessment and the healthy example opens nothing.
        Assert.Empty(await _host.FindingsAsync());
        Assert.Equal("pass", (await _host.AssessmentsAsync("WIN-002", "current")).Single().Result);
        Assert.Equal("pass", (await _host.AssessmentsAsync("SYS-002", "current")).Single().Result);
        Assert.Equal("build_not_in_catalog", (await _host.AssessmentsAsync("SYS-003", "current")).Single().ReasonCode);
        Assert.Null((await _host.AssessmentsAsync("SYS-001", "current")).Single().Result);
    }

    [Fact]
    public async Task A_failing_check_opens_a_finding_and_a_passing_batch_closes_it()
    {
        var agent = await _host.EnrolledAsync();
        var bad = agent.Batch(edit: b => FakeAgent.ObservationOf(b, "WIN-002")["evidence"]!["protectionStatus"] = "off");
        Assert.Equal(HttpStatusCode.OK, (await agent.SubmitAsync(bad)).Status);
        var finding = Assert.Single(await _host.FindingsAsync());
        Assert.Equal(("WIN-002", "open", "critical"), (finding.CheckId, finding.TechnicalState, finding.Severity));
        Assert.Equal(["opened/source_change"], await _host.EventsAsync());

        _host.Clock.Set(_host.Clock.GetUtcNow().AddHours(4));
        await agent.StartSessionAsync();
        Assert.Equal(HttpStatusCode.OK, (await agent.SubmitAsync(agent.Batch())).Status);
        Assert.Equal(["opened/source_change", "resolved/source_change"], await _host.EventsAsync());
    }

    [Fact]
    public async Task A_repeat_of_the_registration_returns_the_first_answer()
    {
        using var agent = _host.NewAgent();
        var (body, _) = await agent.EnrollBodyAsync();
        var first = await agent.EnrollRawAsync(body);
        var second = await agent.EnrollRawAsync(body);
        Assert.Equal((HttpStatusCode.Created, HttpStatusCode.Created), (first.Status, second.Status));
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(first.Text), JsonNode.Parse(second.Text)));
        Assert.Single(await _host.SubjectsAsync("device"));
    }

    [Fact]
    public async Task A_revoked_device_is_stopped_at_its_next_request()
    {
        var agent = await _host.EnrolledAsync();
        var revoked = await _host.Admin.PostAsync($"/api/v1/organizations/{_host.Org}/devices/{agent.DeviceId}/revoke", new { });
        Assert.Equal(HttpStatusCode.NoContent, revoked.Status);
        var reply = await agent.SubmitAsync(agent.Batch());
        Assert.Equal((HttpStatusCode.Unauthorized, ProblemCodes.DeviceRevoked), (reply.Status, reply.Code));
        var again = await agent.EnrollAsync();
        Assert.Equal(ProblemCodes.DeviceRevoked, again.Code);
        Assert.Contains(_host.SecurityLog(), r => r.GetProperty("action").GetString() == "device.revoke");
    }

    [Fact]
    public async Task The_portal_lists_devices_and_keys()
    {
        var agent = await _host.EnrolledAsync();
        var devices = await _host.Admin.GetAsync($"/api/v1/organizations/{_host.Org}/devices", "DevicePage");
        Assert.Equal(1, devices.Body.GetProperty("items").GetArrayLength());
        var keys = await _host.Admin.GetAsync($"/api/v1/organizations/{_host.Org}/enrollment-keys", "EnrollmentKeySummaryPage");
        Assert.Equal(1, keys.Body.GetProperty("items")[0].GetProperty("enrolledDevices").GetInt32());
        var renamed = await _host.Admin.PatchAsync($"/api/v1/organizations/{_host.Org}/devices/{agent.DeviceId}", new { displayName = "PC-ANNE-2" }, "Device");
        Assert.Equal("PC-ANNE-2", renamed.Body.GetProperty("displayName").GetString());
    }

    [Fact]
    public async Task A_third_active_key_is_refused()
    {
        await _host.CreateKeyAsync("second");
        var third = await _host.Admin.PostAsync($"/api/v1/organizations/{_host.Org}/enrollment-keys", new { label = "third" });
        Assert.Equal((HttpStatusCode.UnprocessableEntity, ProblemCodes.ValidationFailed), (third.Status, third.Code));
    }

    [Fact]
    public async Task Existing_findings_keep_the_batch_policy_for_history()
    {
        var agent = await _host.EnrolledAsync();
        var batch = agent.Batch();
        await agent.SubmitAsync(batch);
        var count = await _host.ReadAsync(scope => scope.Db.Observations.CountAsync(o => o.Source == "agent", Ct));
        Assert.Equal(11, count);
        var server = await _host.ReadAsync(scope => scope.Db.Observations.CountAsync(o => o.Source == "server", Ct));
        Assert.True(server >= 3);
    }
}
