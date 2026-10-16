using System.Net;
using System.Text.Json.Nodes;
using Sikkerheit.Agent.Runtime;

namespace Sikkerheit.Agent.Tests;

/// <summary>Delivery of batches: retries, limits, resynchronization (05, "Порядок приёма пакета", "Ошибки и действия агента").</summary>
public sealed class EngineFlowTests
{
    private const string Enrollments = "/api/v1/agent/enrollments";
    private const string CheckIns = "/api/v1/agent/check-ins";
    private const string Scans = "/api/v1/agent/scans";

    [Fact]
    public async Task Offline_for_seven_days_the_batches_stay_in_the_buffer_and_go_out_from_the_old_to_the_new()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();
        f.Server.Script("/api/v1/agent/sessions", _ => throw new HttpRequestException("offline"));
        f.Server.Script("/api/v1/agent/challenges", _ => throw new HttpRequestException("offline"));

        for (var day = 0; day < 4; day++)
        {
            f.Advance(TimeSpan.FromHours(25));
            await f.StepAsync(3);
        }

        Assert.True(f.Buffer.Count >= 3);
        var sequences = f.Buffer.All().Select(b => b.Sequence).ToList();
        Assert.Equal(sequences.OrderBy(x => x), sequences);

        f.Server.ClearScripts();
        f.Advance(TimeSpan.FromHours(2));
        await f.StepAsync(8);

        Assert.Equal(0, f.Buffer.Count);
        var accepted = f.Server.Accepted.Select(b => b["sequence"]!.GetValue<long>()).ToList();
        Assert.Equal(accepted.OrderBy(x => x), accepted);
    }

    [Fact]
    public async Task Buffer_keeps_only_max_buffer_days_when_the_pc_is_offline_longer()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();
        f.Server.Script("/api/v1/agent/challenges", _ => throw new HttpRequestException("offline"));
        f.Server.Script(CheckIns, _ => throw new HttpRequestException("offline"));

        for (var day = 0; day < 10; day++)
        {
            f.Advance(TimeSpan.FromHours(25));
            await f.StepAsync(2);
        }

        Assert.True(f.Buffer.Count <= 7);
        Assert.True(f.Buffer.DroppedBatchCount >= 2);
    }

    [Fact]
    public async Task A_lost_registration_answer_is_repeated_with_the_same_bytes_and_creates_one_device()
    {
        using var f = new AgentFixture();
        f.Server.LoseResponses(Enrollments, 1);
        f.DropKeyFile();

        await f.StepAsync(1);
        Assert.Equal(AgentState.Backoff, f.Engine.State);
        f.Advance(TimeSpan.FromMinutes(3));
        await f.StepAsync(4);

        var attempts = f.Seen(Enrollments).ToList();
        Assert.Equal(2, attempts.Count);
        Assert.Equal(attempts[0].Body, attempts[1].Body);
        Assert.Single(f.Server.Devices);
        Assert.Equal(AgentState.Active, f.Engine.State);
    }

    [Fact]
    public async Task Registration_is_repeated_with_a_new_request_id_after_idempotency_conflict()
    {
        using var f = new AgentFixture();
        var conflict = true;
        f.Server.Script(Enrollments, _ => conflict ? FakeServer.Problem(HttpStatusCode.Conflict, "idempotency_conflict") : null);
        f.DropKeyFile();
        await f.StepAsync(1);
        conflict = false;

        await f.StepAsync(4);

        var requests = f.Seen(Enrollments).Select(r => r.Json["registrationRequestId"]!.GetValue<string>()).ToList();
        Assert.Equal(2, requests.Distinct().Count());
        Assert.Equal(AgentState.Active, f.Engine.State);
    }

    [Fact]
    public async Task Requests_have_the_headers_and_the_media_type_of_the_contract()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();

        var enroll = f.Seen(Enrollments).Single();
        var scan = f.Seen(Scans).Single();

        Assert.Equal("Enrollment " + f.OrganizationKey, enroll.Headers["Authorization"]);
        Assert.StartsWith("application/json", scan.Headers["Content-Type"]);
        Assert.StartsWith("Bearer ", scan.Headers["Authorization"]);
        Assert.Equal(scan.Json["scanId"]!.GetValue<string>(), scan.Headers["Idempotency-Key"]);
        Assert.Matches(@"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$", scan.Headers["Sikkerheit-Sent-At"]);
        Assert.False(scan.Headers.ContainsKey("Content-Encoding"));
        Assert.DoesNotContain(f.OrganizationKey, System.Text.Encoding.UTF8.GetString(scan.Body));
    }

    [Fact]
    public async Task A_batch_rejected_with_schema_violation_is_dropped_the_configuration_is_refreshed_and_the_queue_goes_on()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();
        var reject = true;
        f.Server.Script(Scans, _ => reject ? FakeServer.Problem(HttpStatusCode.UnprocessableEntity, "schema_violation") : null);
        var checkIns = f.Count(CheckIns);

        f.Advance(TimeSpan.FromHours(25));
        await f.StepAsync(1);
        reject = false;
        await f.StepAsync(2);

        Assert.Equal(0, f.Buffer.Count);
        Assert.Equal(1, f.Buffer.RejectedBatchCount);
        Assert.True(f.Count(CheckIns) > checkIns);
        await f.StepAsync(1);
        f.Advance(TimeSpan.FromHours(5));
        await f.StepAsync(2);
        Assert.Equal(1, f.Server.Devices.Values.Single().LastCheckIn!["rejectedBatchCount"]!.GetValue<int>());
    }

    [Fact]
    public async Task Sequence_conflict_after_a_restore_of_the_pc_renumbers_the_queue_from_the_last_accepted_sequence()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();
        // The server accepted sequences up to 40 after the checkpoint of the PC; the agent knows only 1.
        var device = f.Server.Devices.Values.Single();
        device.LastAcceptedSequence = 40;
        device.LastAcceptedCompletedAt = AgentFixture.Start - TimeSpan.FromHours(1);

        f.Advance(TimeSpan.FromHours(25));
        await f.StepAsync(4);

        var last = f.Server.Accepted.Last();
        Assert.Equal(41, last["sequence"]!.GetValue<int>());
        Assert.Equal(0, f.Buffer.Count);
        Assert.Contains(f.Server.Requests, r => r.Path == Scans && r.Code == "sequence_conflict");
        Assert.Equal(AgentState.Active, f.Engine.State);
    }

    [Fact]
    public async Task Temporarily_unavailable_with_retry_after_waits_for_the_given_time_then_repeats()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();
        var unavailable = true;
        f.Server.Script(Scans, _ => unavailable ? FakeServer.Problem(HttpStatusCode.ServiceUnavailable, "temporarily_unavailable", retryAfter: "120") : null);

        f.Advance(TimeSpan.FromHours(25));
        await f.StepAsync(1);
        Assert.Equal(AgentState.Backoff, f.Engine.State);
        var attempts = f.Count(Scans);

        unavailable = false;
        f.Advance(TimeSpan.FromSeconds(60));
        await f.StepAsync(2);
        Assert.Equal(attempts, f.Count(Scans));

        f.Advance(TimeSpan.FromSeconds(70));
        await f.StepAsync(2);
        Assert.Equal(AgentState.Active, f.Engine.State);
        Assert.Equal(0, f.Buffer.Count);
    }

    [Fact]
    public async Task Rate_limited_and_answers_without_problem_use_exponential_backoff_with_a_cap_of_one_hour()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();
        f.Server.Script(Scans, _ => new HttpResponseMessage(HttpStatusCode.BadGateway));
        f.Advance(TimeSpan.FromHours(25));
        await f.StepAsync(1);

        var waits = new List<TimeSpan>();
        for (var i = 0; i < 9; i++)
        {
            var until = f.State.GetTime("backoffUntil")!.Value;
            waits.Add(until - f.Time.GetUtcNow());
            f.Advance(until - f.Time.GetUtcNow() + TimeSpan.FromSeconds(1));
            await f.StepAsync(1);
        }

        Assert.All(waits, w => Assert.InRange(w, TimeSpan.FromSeconds(40), TimeSpan.FromMinutes(72)));
        Assert.True(waits[4] > waits[0]);
        Assert.True(waits[8] > TimeSpan.FromMinutes(40));
    }

    [Fact]
    public async Task A_batch_with_five_answers_500_and_check_ins_between_the_attempts_is_deleted_like_drop_batch()
    {
        using var f = new AgentFixture();
        f.Server.ConfigurationOverrides["scanIntervalHours"] = 168; // one batch in the test
        await f.EnrolledAsync();
        f.Server.Script(Scans, _ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        f.Advance(TimeSpan.FromHours(169));
        await f.StepAsync(1); // the scan and the first answer 500

        for (var i = 0; i < 30 && f.Buffer.Count > 0; i++)
        {
            f.Advance(TimeSpan.FromHours(5)); // the backoff is over and the check-in is due
            await f.StepAsync(1);
        }

        Assert.Equal(0, f.Buffer.Count);
        Assert.Equal(1, f.Buffer.RejectedBatchCount);
        Assert.Equal(5, f.Server.Requests.Count(r => r.Path == Scans && r.Status == 500));
    }

    [Fact]
    public async Task A_stale_token_is_renewed_and_the_request_is_repeated()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();
        var sessions = f.Count("/api/v1/agent/sessions");
        var expire = true;
        f.Server.Script(Scans, _ =>
        {
            if (!expire)
            {
                return null;
            }
            expire = false;
            return FakeServer.Problem(HttpStatusCode.Unauthorized, "session_invalid");
        });

        f.Advance(TimeSpan.FromHours(25));
        await f.StepAsync(3);

        Assert.Equal(0, f.Buffer.Count);
        Assert.Equal(sessions + 2, f.Count("/api/v1/agent/sessions")); // the expired token and the one that the server did not accept
        Assert.Equal(AgentState.Active, f.Engine.State);
    }

    [Fact]
    public async Task Restart_of_the_service_counts_a_start_and_a_crash_but_a_clean_stop_is_not_a_crash()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();

        f.Advance(TimeSpan.FromMinutes(10));
        await f.StepAsync(1);
        f.Restart(); // the process died: Shutdown was not called

        Assert.Equal(2, f.State.GetLong("serviceStarts"));
        Assert.NotNull(f.State.GetTime("lastCrashAt"));

        f.State.Set("lastCrashAt", null);
        f.Engine.Shutdown();
        f.Restart();
        Assert.Equal(3, f.State.GetLong("serviceStarts"));
        Assert.Null(f.State.GetTime("lastCrashAt"));
    }

    [Fact]
    public async Task State_and_device_survive_a_restart_of_the_service()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();
        var device = f.Engine.DeviceId;

        f.Restart();
        f.Advance(TimeSpan.FromHours(5));
        await f.StepAsync(3);

        Assert.Equal(device, f.Engine.DeviceId);
        Assert.Equal(AgentState.Active, f.Engine.State);
        Assert.Single(f.Server.Devices);
        Assert.NotNull(f.Engine.Configuration);
    }

    [Fact]
    public async Task Collection_continues_into_the_buffer_while_the_enrollment_is_blocked_with_a_stored_configuration()
    {
        using var f = new AgentFixture();
        await f.EnrolledAsync();
        f.Server.ForgetDevices();
        f.Server.ValidKeys.Clear();
        f.Advance(TimeSpan.FromHours(5));
        await f.StepAsync(6);
        Assert.Equal(AgentState.EnrollmentBlocked, f.Engine.State);
        var before = f.Buffer.Count;

        f.Advance(TimeSpan.FromHours(25));
        await f.StepAsync(2);

        Assert.True(f.Buffer.Count > before);
    }
}
