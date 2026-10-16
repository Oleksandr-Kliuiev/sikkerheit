using Sikkerheit.Agent.Runtime;
using Sikkerheit.Agent.Storage;

namespace Sikkerheit.Agent.Tests;

public sealed class EngineHappyPathTests
{
    [Fact]
    public async Task Key_file_is_saved_protected_and_deleted_and_the_agent_registers_and_sends_the_first_batch()
    {
        using var f = new AgentFixture();
        f.DropKeyFile();

        await f.StepAsync(4);

        Assert.False(File.Exists(f.Paths.IncomingKeyFile));
        Assert.True(File.Exists(f.Paths.ProtectedKeyFile));
        Assert.DoesNotContain(f.OrganizationKey, File.ReadAllText(f.Paths.ProtectedKeyFile, System.Text.Encoding.Latin1));
        Assert.Equal(AgentState.Active, f.Engine.State);
        Assert.Single(f.Server.Devices);
        Assert.Equal(f.Server.Devices.Keys.Single(), f.Engine.DeviceId);
        Assert.Single(f.Server.Accepted);
        Assert.Equal(0, f.Buffer.Count);
        Assert.Empty(f.Server.SchemaViolations);
    }

    [Fact]
    public async Task Full_batch_has_an_observation_for_every_active_check_and_the_os_volume_subject()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();

        var batch = f.Server.Accepted.Single();
        var ids = batch["observations"]!.AsArray().Select(o => o!["checkId"]!.GetValue<string>()).ToList();

        Assert.Equal(StubCollectors.CheckIds, ids);
        Assert.Equal(1, batch["sequence"]!.GetValue<int>());
        Assert.Equal("2.0", batch["schemaVersion"]!.GetValue<string>());
        Assert.Equal(FakeVolume.Os.VolumeId, batch["observations"]![0]!["subject"]!["volumeId"]!.GetValue<string>());
    }

    [Fact]
    public async Task Planned_collection_waits_60_minutes_after_boot()
    {
        using var f = new AgentFixture();
        f.Probe.BootTime = AgentFixture.Start - TimeSpan.FromMinutes(10);
        await f.EnrolledAsync();

        Assert.Empty(f.Server.Accepted);
        Assert.Equal(0, f.Buffer.Count);

        f.Advance(TimeSpan.FromMinutes(51));
        await f.StepAsync(2);

        Assert.Single(f.Server.Accepted);
    }

    [Fact]
    public async Task Check_in_carries_the_telemetry_and_the_fingerprint()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();

        var checkIn = f.Server.Devices.Values.Single().LastCheckIn!;

        Assert.Equal("0.1.0", checkIn["agentVersion"]!.GetValue<string>());
        Assert.Equal(1, checkIn["configSchemaVersion"]!.GetValue<int>());
        Assert.Equal(1, checkIn["serviceStarts"]!.GetValue<int>());
        Assert.Equal("PC-TEST-01", checkIn["reportedDisplayName"]!.GetValue<string>());
        Assert.Equal(64, checkIn["machineFingerprint"]!.GetValue<string>().Length);
        Assert.False(checkIn["configRejected"]!.GetValue<bool>());
        Assert.Null(checkIn["lastCrashAt"]);
    }

    [Fact]
    public async Task Second_scan_runs_after_the_interval_with_the_next_sequence()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();

        f.Advance(TimeSpan.FromHours(25));
        await f.StepAsync(3);

        Assert.Equal(2, f.Server.Accepted.Count);
        Assert.Equal(2, f.Server.Accepted[1]["sequence"]!.GetValue<int>());
    }

    [Fact]
    public async Task Pending_scan_request_makes_an_immediate_scan_with_the_scan_request_id()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();
        var request = Guid.NewGuid().ToString("D");
        f.Server.PendingScanRequestId = request;

        f.Advance(TimeSpan.FromHours(5)); // the next check-in brings the request
        await f.StepAsync(4);

        Assert.Equal(request, f.Server.Accepted.Last()["scanRequestId"]!.GetValue<string>());
    }
}
