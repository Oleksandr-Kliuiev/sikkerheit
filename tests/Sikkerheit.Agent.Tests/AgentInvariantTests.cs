using System.Net;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Sikkerheit.Agent.Runtime;
using Sikkerheit.Agent.Storage;

namespace Sikkerheit.Agent.Tests;

/// <summary>
/// Records of invariants.json with enforcement "agent" that are checked without Windows (WP-09): the agent against the fake server.
/// The records that need the real collectors are in CollectorInvariantTests; INV-153 also there.
/// </summary>
public sealed class AgentInvariantTests
{
    private const string Challenges = "/api/v1/agent/challenges";
    private const string Enrollments = "/api/v1/agent/enrollments";
    private const string Sessions = "/api/v1/agent/sessions";
    private const string CheckIns = "/api/v1/agent/check-ins";
    private const string Scans = "/api/v1/agent/scans";

    [Fact]
    [Invariant("INV-105")]
    public async Task Inv105_device_unknown_registers_again_with_the_stored_organization_key_without_a_technician()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();
        var first = f.Engine.DeviceId;
        f.Server.ForgetDevices(); // restore of the database to a point before the registration

        f.Advance(TimeSpan.FromHours(5));
        await f.StepAsync(6);

        Assert.Equal(AgentState.Active, f.Engine.State);
        Assert.NotEqual(first, f.Engine.DeviceId);
        Assert.Single(f.Server.Devices);
        Assert.Equal(1, f.Keys.Created); // the stored device key is reused
        Assert.Contains(f.Server.Requests, r => r.Path == Sessions && r.Code == "device_unknown");
    }

    [Fact]
    [Invariant("INV-106")]
    public async Task Inv106_second_challenge_invalid_registers_again_with_the_same_installation_id_not_more_than_once_a_day()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();
        var installation = File.ReadAllText(f.Paths.InstallationIdFile);
        var challenge = 0;
        f.Server.Script(Sessions, _ => ++challenge <= 4 ? FakeServer.Problem(HttpStatusCode.Unauthorized, "challenge_invalid") : null);

        f.Advance(TimeSpan.FromHours(5)); // the token expired and the check-in is due
        await f.StepAsync(4);

        var enrollments = f.Seen(Enrollments).ToList();
        Assert.Equal(2, enrollments.Count);
        Assert.Equal(installation.Trim(), enrollments[1].Json["installationId"]!.GetValue<string>());
        Assert.Single(f.Server.Devices);

        // The day limit: the second pair of refusals does not start one more registration within 24 hours.
        challenge = 0;
        f.Advance(TimeSpan.FromHours(5));
        await f.StepAsync(4);
        Assert.Equal(2, f.Count(Enrollments));
    }

    [Fact]
    [Invariant("INV-106")]
    public async Task Inv106_server_that_remembers_another_key_answers_identity_conflict_of_the_kind_key()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();
        // The database is restored to a point before the replacement of the key: the server holds another key of the device.
        var device = f.Server.Devices.Values.Single();
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        device.Replace(other, Sikkerheit.Agent.Protocol.PublicKeyJwk.FromParameters(other.ExportParameters(false)));
        var thumbprint = device.Thumbprint;

        f.Advance(TimeSpan.FromHours(5));
        await f.StepAsync(5);

        Assert.Equal(AgentState.IdentityConflict, f.Engine.State);
        Assert.Equal(thumbprint, device.Thumbprint);
        Assert.NotNull(device.RejectedKey);
        Assert.Contains(f.Server.Requests, r => r.Path == Enrollments && r.Code == "identity_conflict");
    }

    [Fact]
    [Invariant("INV-107")]
    public async Task Inv107_enrollment_key_invalid_blocks_the_enrollment_and_retries_once_a_day_until_a_new_key_arrives()
    {
        using var f = new AgentFixture();
        f.DropKeyFile("sikk_" + new string('A', 43));
        await f.StepAsync(3);

        Assert.Equal(AgentState.EnrollmentBlocked, f.Engine.State);
        Assert.Equal(1, f.Count(Enrollments));

        f.Advance(TimeSpan.FromHours(3));
        await f.StepAsync(3);
        Assert.Equal(1, f.Count(Enrollments));

        f.Advance(TimeSpan.FromHours(22));
        await f.StepAsync(3);
        Assert.Equal(2, f.Count(Enrollments));
        Assert.Equal(AgentState.EnrollmentBlocked, f.Engine.State);

        f.DropKeyFile(); // a new key from RMM: the registration is immediate
        f.Advance(TimeSpan.FromMinutes(2));
        await f.StepAsync(4);
        Assert.Equal(AgentState.Active, f.Engine.State);
    }

    [Fact]
    [Invariant("INV-108")]
    public async Task Inv108_after_deletion_of_the_organization_device_unknown_is_followed_by_enrollment_key_invalid_and_blocked_enrollment()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();
        f.Server.ForgetDevices();
        f.Server.ValidKeys.Clear(); // the organization is deleted with its keys

        f.Advance(TimeSpan.FromHours(5));
        await f.StepAsync(6);

        Assert.Equal(AgentState.EnrollmentBlocked, f.Engine.State);
        Assert.Contains(f.Server.Requests, r => r.Code == "device_unknown");
        Assert.Contains(f.Server.Requests, r => r.Path == Enrollments && r.Code == "enrollment_key_invalid");
    }

    [Fact]
    [Invariant("INV-109")]
    public async Task Inv109_device_revoked_deletes_the_key_and_the_buffer_and_the_agent_makes_no_more_requests()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();
        f.Server.Devices.Values.Single().Revoked = true;

        f.Advance(TimeSpan.FromHours(5));
        await f.StepAsync(4);

        Assert.Equal(AgentState.Revoked, f.Engine.State);
        Assert.False(f.Keys.Exists);
        Assert.Equal(0, f.Buffer.Count);
        var requests = f.Server.Requests.Count;

        f.DropKeyFile(); // even a new key does not return the installation to work
        f.Advance(TimeSpan.FromDays(3));
        await f.StepAsync(5);
        f.Restart();
        await f.StepAsync(5);

        Assert.Equal(AgentState.Revoked, f.Engine.State);
        Assert.Equal(requests, f.Server.Requests.Count);
    }

    [Fact]
    [Invariant("INV-110")]
    public async Task Inv110_organization_inactive_suspends_sending_and_the_check_in_runs_once_a_day()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();
        f.Server.OrganizationActive = false;

        f.Advance(TimeSpan.FromHours(25)); // a scan is due, the check-in too
        await f.StepAsync(4);

        Assert.Equal(AgentState.Suspended, f.Engine.State);
        Assert.Single(f.Server.Accepted);
        Assert.True(f.Buffer.Count >= 1); // the collection continues into the buffer
        var scans = f.Count(Scans);
        var checkIns = f.Count(CheckIns);

        f.Advance(TimeSpan.FromHours(10));
        await f.StepAsync(3);
        Assert.Equal(scans, f.Count(Scans));
        Assert.Equal(checkIns, f.Count(CheckIns));

        f.Advance(TimeSpan.FromHours(15));
        await f.StepAsync(3);
        Assert.True(f.Count(CheckIns) + f.Count(Sessions) > checkIns); // the daily attempt

        f.Server.OrganizationActive = true;
        f.Advance(TimeSpan.FromHours(25));
        await f.StepAsync(5);
        Assert.Equal(AgentState.Active, f.Engine.State);
        Assert.Equal(0, f.Buffer.Count);
    }

    [Fact]
    [Invariant("INV-111")]
    public async Task Inv111_agent_version_unsupported_stops_sending_while_the_check_in_continues_every_4_hours()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();
        f.Server.Script(Scans, _ => FakeServer.Problem(HttpStatusCode.UnprocessableEntity, "agent_version_unsupported", minimum: "0.2.0"));
        f.Server.MinimumAgentVersion = "0.2.0";
        f.Advance(TimeSpan.FromHours(25));
        await f.StepAsync(3);

        Assert.Equal(AgentState.VersionBlocked, f.Engine.State);
        Assert.Equal(1, f.Buffer.Count); // the batch is kept
        var scans = f.Count(Scans);
        var checkIns = f.Count(CheckIns);

        f.Advance(TimeSpan.FromHours(1));
        await f.StepAsync(3);
        Assert.Equal(checkIns, f.Count(CheckIns));

        f.Advance(TimeSpan.FromHours(4));
        await f.StepAsync(3);
        Assert.Equal(checkIns + 1, f.Count(CheckIns));
        Assert.Equal(scans, f.Count(Scans)); // the configuration still forbids the version: no trial batch
        Assert.Equal(AgentState.VersionBlocked, f.Engine.State);
    }

    [Fact]
    public async Task Version_block_ends_with_one_trial_batch_when_the_configuration_allows_the_version()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();
        var blocked = true;
        f.Server.Script(Scans, _ => blocked ? FakeServer.Problem(HttpStatusCode.UnprocessableEntity, "agent_version_unsupported", minimum: "0.2.0") : null);
        f.Advance(TimeSpan.FromHours(25));
        await f.StepAsync(3);
        Assert.Equal(AgentState.VersionBlocked, f.Engine.State);

        blocked = false;
        f.Advance(TimeSpan.FromHours(5));
        await f.StepAsync(3);

        Assert.Equal(AgentState.Active, f.Engine.State);
        Assert.Equal(0, f.Buffer.Count);
    }

    [Fact]
    public async Task A_new_version_of_the_agent_from_rmm_leaves_version_blocked_at_start()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();
        f.State.Set(StateKeys.State, nameof(AgentState.VersionBlocked));
        f.State.Set(StateKeys.BlockedVersion, "0.0.9");

        f.Restart();

        Assert.Equal(AgentState.Active, f.Engine.State);
    }

    [Fact]
    [Invariant("INV-113")]
    public async Task Inv113_identity_conflict_stops_sending_until_the_resolution()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();
        var device = f.Server.Devices.Values.Single();
        var real = device.Fingerprint;
        device.Fingerprint = new string('a', 64); // the clone / the replaced board is another machine for the server

        f.Advance(TimeSpan.FromHours(25));
        await f.StepAsync(4);

        Assert.Equal(AgentState.IdentityConflict, f.Engine.State);
        var scans = f.Count(Scans);
        f.Advance(TimeSpan.FromHours(10));
        await f.StepAsync(3);
        Assert.Equal(scans, f.Count(Scans));
        Assert.True(f.Buffer.Count >= 1);

        device.Fingerprint = real; // resolveDeviceIdentity
        f.Advance(TimeSpan.FromHours(25));
        await f.StepAsync(5);
        Assert.Equal(AgentState.Active, f.Engine.State);
        Assert.Equal(0, f.Buffer.Count);
    }

    [Fact]
    [Invariant("INV-114")]
    public async Task Inv114_invalid_value_of_one_observation_makes_only_it_unavailable_and_the_other_checks_are_accepted()
    {
        using var f = new AgentFixture(() => StubCollectors.With("WIN-002", _ =>
            Sikkerheit.Agent.Collectors.CollectorOutcome.Collected((JsonObject)JsonNode.Parse(
                """{"volumeStatus":"mystery","protectionStatus":"on","encryptionPercentage":100}""")!)));
        await f.EnrolledAsync();

        var observations = f.Server.Accepted.Single()["observations"]!.AsArray();
        var bad = observations.Single(o => o!["checkId"]!.GetValue<string>() == "WIN-002")!;

        Assert.Equal("unavailable", bad["collectionStatus"]!.GetValue<string>());
        Assert.Equal("unsupported", bad["reasonCode"]!.GetValue<string>());
        Assert.Null(bad["evidence"]);
        Assert.Equal(10, observations.Count(o => o!["collectionStatus"]!.GetValue<string>() == "collected"));
        Assert.Empty(f.Server.SchemaViolations);
    }

    [Fact]
    [Invariant("INV-116")]
    public async Task Inv116_configuration_with_a_field_outside_the_schema_is_rejected_whole_and_the_agent_goes_on_with_the_previous_one()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();
        var before = f.Engine.Configuration!;
        f.Server.ConfigurationOverrides["command"] = "calc.exe";
        f.Server.ConfigurationOverrides["scanIntervalHours"] = 1;

        f.Advance(TimeSpan.FromHours(5));
        await f.StepAsync(3);

        Assert.Equal(before, f.Engine.Configuration);
        Assert.Equal(24, f.Engine.Configuration!.ScanIntervalHours);

        f.Server.ConfigurationOverrides.Clear();
        f.Advance(TimeSpan.FromHours(5));
        await f.StepAsync(3);
        var reported = f.Server.Devices.Values.Single().LastCheckIn!;
        Assert.True(reported["configRejected"]!.GetValue<bool>()); // the check-in reports the rejection once
        f.Advance(TimeSpan.FromHours(5));
        await f.StepAsync(3);
        Assert.False(f.Server.Devices.Values.Single().LastCheckIn!["configRejected"]!.GetValue<bool>());
    }
}
