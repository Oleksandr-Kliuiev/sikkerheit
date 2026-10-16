using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Sikkerheit.Contracts;
using Sikkerheit.ContractTests.Invariants;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.ContractTests;

/// <summary>
/// Records enforced by the agent API (05 «API агента»): each test sends the negative example of the record to the service
/// over HTTP with a test agent that signs as the contract says, and expects the error or the effect of the record.
/// </summary>
[Enforcement("agent_api")]
public sealed class AgentApiInvariantTests(PostgresFixture postgres) : IAsyncLifetime
{
    private AgentHost _host = null!;

    public async ValueTask InitializeAsync() => _host = await AgentHost.StartAsync(postgres);

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    private static CancellationToken Ct => AgentHost.Ct;

    private static void Refused(FakeAgent.Reply reply, HttpStatusCode status, string code) =>
        Assert.Equal((status, code), (reply.Status, reply.Code));

    private Task<int> CountAsync<T>(Func<Sikkerheit.Host.Data.SikkerheitDb, IQueryable<T>> set) =>
        _host.ReadAsync(scope => set(scope.Db).CountAsync(Ct));

    private static ECDsa NewKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    [Fact]
    [Invariant("INV-086")]
    public async Task Inv086_challenge_body_over_1024_bytes_is_refused_before_it_is_parsed()
    {
        using var agent = _host.NewAgent();
        // The body is not JSON: 413 shows that the size is checked first.
        var reply = await agent.SendAsync("/api/v1/agent/challenges", new string('x', 2048), null);
        Refused(reply, HttpStatusCode.RequestEntityTooLarge, ProblemCodes.PayloadTooLarge);
        var small = await agent.ChallengeAsync();
        Assert.Equal(HttpStatusCode.Created, small.Status);
    }

    [Fact]
    [Invariant("INV-087")]
    public async Task Inv087_nonce_is_single_use_and_bound_to_its_purpose_and_device()
    {
        var agent = await _host.EnrolledAsync();
        var nonce = await agent.NonceAsync("session");
        Assert.Equal(HttpStatusCode.Created, (await agent.SessionAsync(nonce)).Status);
        Refused(await agent.SessionAsync(nonce), HttpStatusCode.Unauthorized, ProblemCodes.ChallengeInvalid);

        // A nonce for registration does not open a session, and a nonce of another device does not either.
        Refused(await agent.SessionAsync(await agent.NonceAsync("enroll")), HttpStatusCode.Unauthorized, ProblemCodes.ChallengeInvalid);
        var other = await _host.EnrolledAsync("PC-OLA");
        Refused(await agent.SessionAsync(await other.NonceAsync("session")), HttpStatusCode.Unauthorized, ProblemCodes.ChallengeInvalid);
        // A nonce older than five minutes is not valid.
        var stale = await agent.NonceAsync("session");
        _host.Clock.Set(_host.Clock.GetUtcNow().AddMinutes(6));
        Refused(await agent.SessionAsync(stale), HttpStatusCode.Unauthorized, ProblemCodes.ChallengeInvalid);
    }

    [Fact]
    [Invariant("INV-088")]
    public async Task Inv088_a_signature_by_another_key_creates_no_device()
    {
        using var agent = _host.NewAgent();
        using var other = NewKey();
        Refused(await agent.EnrollAsync(new FakeAgent.EnrollOptions { SigningKey = other }), HttpStatusCode.Unauthorized,
            ProblemCodes.ChallengeInvalid);
        Assert.Equal(0, await CountAsync(db => db.Devices));
        Assert.Equal(0, await CountAsync(db => db.Subjects.Where(s => s.Type == "device")));
    }

    [Fact]
    [Invariant("INV-089")]
    public async Task Inv089_an_unknown_or_revoked_enrollment_key_creates_no_device()
    {
        using var unknown = _host.NewAgent();
        Refused(await unknown.EnrollAsync(new FakeAgent.EnrollOptions { Key = "sikk_" + new string('A', 43) }),
            HttpStatusCode.Unauthorized, ProblemCodes.EnrollmentKeyInvalid);
        var (keyId, secret) = await _host.CreateKeyAsync("second");
        var revoked = await _host.Admin.PostAsync($"/api/v1/organizations/{_host.Org}/enrollment-keys/{keyId}/revoke", new { });
        Assert.Equal(HttpStatusCode.NoContent, revoked.Status);
        using var late = _host.NewAgent();
        Refused(await late.EnrollAsync(new FakeAgent.EnrollOptions { Key = secret }), HttpStatusCode.Unauthorized,
            ProblemCodes.EnrollmentKeyInvalid);
        Assert.Equal(0, await CountAsync(db => db.Devices));
        Assert.Contains(_host.SecurityLog(), r => r.GetProperty("action").GetString() == "enrollment_key.revoke");
    }

    [Fact]
    [Invariant("INV-090")]
    public async Task Inv090_registration_in_a_disabled_organization_is_refused()
    {
        Assert.Equal(HttpStatusCode.OK, (await _host.LifecycleAsync("disable")).Status);
        using var agent = _host.NewAgent();
        Refused(await agent.EnrollAsync(), HttpStatusCode.Forbidden, ProblemCodes.OrganizationInactive);
        Assert.Equal(0, await CountAsync(db => db.Devices));
    }

    [Fact]
    [Invariant("INV-091")]
    public async Task Inv091_an_identical_repeat_of_the_registration_creates_no_second_device()
    {
        using var agent = _host.NewAgent();
        var (body, _) = await agent.EnrollBodyAsync();
        var first = await agent.EnrollRawAsync(body);
        var repeat = await agent.EnrollRawAsync(body);
        Assert.Equal((HttpStatusCode.Created, HttpStatusCode.Created), (first.Status, repeat.Status));
        Assert.Equal(first.Body.GetProperty("deviceId").GetString(), repeat.Body.GetProperty("deviceId").GetString());
        Assert.Equal(1, await CountAsync(db => db.Devices));
        Assert.Equal(1, await CountAsync(db => db.Enrollments));
    }

    [Fact]
    [Invariant("INV-092")]
    public async Task Inv092_a_repeat_is_checked_before_the_status_of_the_key()
    {
        using var agent = _host.NewAgent();
        var (body, _) = await agent.EnrollBodyAsync();
        Assert.Equal(HttpStatusCode.Created, (await agent.EnrollRawAsync(body)).Status);
        // The key is rotated out; the answer to the first call was lost.
        await _host.Admin.PostAsync($"/api/v1/organizations/{_host.Org}/enrollment-keys/{_host.KeyId}/revoke", new { });
        var repeat = await agent.EnrollRawAsync(body);
        Assert.Equal(HttpStatusCode.Created, repeat.Status);
        // A new request with the revoked key is refused: only the repeat gets through.
        Refused(await agent.EnrollAsync(), HttpStatusCode.Unauthorized, ProblemCodes.EnrollmentKeyInvalid);
        Assert.Equal(1, await CountAsync(db => db.Devices));
    }

    [Fact]
    [Invariant("INV-093")]
    public async Task Inv093_registering_again_with_the_same_key_replaces_nothing()
    {
        using var agent = _host.NewAgent();
        var id = await agent.EnrollOkAsync();
        var again = await agent.EnrollAsync();
        Assert.Equal(HttpStatusCode.Created, again.Status);
        Assert.True(again.Body.GetProperty("reenrolled").GetBoolean());
        Assert.Equal(id.ToString(), again.Body.GetProperty("deviceId").GetString());
        Assert.Empty(await _host.AuditAsync("device.key_replaced"));
        Assert.Equal(1, await CountAsync(db => db.Devices));
    }

    [Fact]
    [Invariant("INV-094")]
    public async Task Inv094_challenges_write_nothing_and_a_spent_nonce_stays_spent_after_a_restart()
    {
        var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        await _host.DisposeAsync();
        _host = await AgentHost.StartAsync(postgres, f => f.Settings["Agents:NonceKey"] = key);
        var agent = await _host.EnrolledAsync();
        var spent = await _host.ReadAsync(async scope =>
            await scope.Db.Database.SqlQuery<long>($"select count(*) as \"Value\" from agent_challenge").SingleAsync(Ct));
        for (var i = 0; i < 5; i++)
        {
            await agent.ChallengeAsync();
        }
        // Only spent nonces are in the database; five challenges added nothing.
        Assert.Equal(spent, await _host.ReadAsync(async scope =>
            await scope.Db.Database.SqlQuery<long>($"select count(*) as \"Value\" from agent_challenge").SingleAsync(Ct)));
        var nonce = await agent.NonceAsync("session");
        Assert.Equal(HttpStatusCode.Created, (await agent.SessionAsync(nonce)).Status);

        await using var restarted = new ApiFactory(_host.Factory.ConnectionString, _host.Factory.SecurityLogDirectory);
        restarted.Settings["Agents:NonceKey"] = key;
        restarted.Clock.Set(_host.Clock.GetUtcNow());
        using var again = new FakeAgent(restarted, _host.KeySecret, agent.InstallationId) { Key = agent.Key, DeviceId = agent.DeviceId };
        Refused(await again.SessionAsync(nonce), HttpStatusCode.Unauthorized, ProblemCodes.ChallengeInvalid);
        // A fresh nonce works on the restarted instance, which proves the key is the same one.
        Assert.Equal(HttpStatusCode.Created, (await again.SessionAsync(await again.NonceAsync("session"))).Status);
    }

    [Fact]
    [Invariant("INV-095")]
    public async Task Inv095_the_same_registration_request_with_another_key_is_a_conflict()
    {
        using var agent = _host.NewAgent();
        var (body, request) = await agent.EnrollBodyAsync();
        Assert.Equal(HttpStatusCode.Created, (await agent.EnrollRawAsync(body)).Status);
        using var otherKey = NewKey();
        var conflict = await agent.EnrollAsync(new FakeAgent.EnrollOptions { RegistrationRequestId = request, PublicKey = otherKey });
        Refused(conflict, HttpStatusCode.Conflict, ProblemCodes.IdempotencyConflict);
    }

    [Fact]
    [Invariant("INV-096")]
    public async Task Inv096_a_revoked_installation_does_not_get_access_back()
    {
        var agent = await _host.EnrolledAsync();
        Assert.Equal(HttpStatusCode.NoContent,
            (await _host.Admin.PostAsync($"/api/v1/organizations/{_host.Org}/devices/{agent.DeviceId}/revoke", new { })).Status);
        Refused(await agent.EnrollAsync(), HttpStatusCode.Unauthorized, ProblemCodes.DeviceRevoked);
        Refused(await agent.SessionAsync(), HttpStatusCode.Unauthorized, ProblemCodes.DeviceRevoked);
        Assert.Equal(1, await CountAsync(db => db.Devices));
    }

    [Fact]
    [Invariant("INV-097")]
    public async Task Inv097_a_clone_with_the_same_installation_id_changes_no_key_and_raises_a_conflict()
    {
        var original = await _host.EnrolledAsync();
        var before = (await _host.DeviceAsync(original.DeviceId!.Value)).KeyThumbprint;
        using var clone = new FakeAgent(_host.Factory, _host.KeySecret, original.InstallationId, "PC-KLON", machineGuid: "0A1B2C3D-0000-4000-8000-00000000AAAA");
        var reply = await clone.EnrollAsync();
        Refused(reply, HttpStatusCode.Conflict, ProblemCodes.IdentityConflict);
        var device = await _host.DeviceAsync(original.DeviceId!.Value);
        Assert.Equal(before, device.KeyThumbprint);
        Assert.Equal(("identity_conflict", "fingerprint", "PC-KLON"), (device.IdentityState, device.ConflictKind, device.ConflictDisplayName));
        // The original goes on working.
        Assert.Equal(HttpStatusCode.OK, (await original.CheckInAsync()).Status);
        Assert.Single(await _host.AuditAsync("device.identity_conflict"));
    }

    [Fact]
    [Invariant("INV-098")]
    public async Task Inv098_a_new_key_replaces_the_old_one_only_with_the_signature_of_the_old_key()
    {
        var agent = await _host.EnrolledAsync();
        var deviceId = agent.DeviceId!.Value;
        var oldKey = agent.Key;
        using var newKey = NewKey();
        var reply = await agent.EnrollAsync(new FakeAgent.EnrollOptions { PublicKey = newKey, PreviousKey = oldKey });
        Assert.Equal(HttpStatusCode.Created, reply.Status);
        Assert.True(reply.Body.GetProperty("reenrolled").GetBoolean());
        Assert.Equal(deviceId.ToString(), reply.Body.GetProperty("deviceId").GetString());
        var device = await _host.DeviceAsync(deviceId);
        Assert.Equal(agent.Thumbprint(newKey), device.KeyThumbprint);
        Assert.Single(await _host.AuditAsync("device.key_replaced"));
        Assert.Equal(1, await CountAsync(db => db.Devices));
        // A signature of some other key is not the old key's: the key stays.
        using var third = NewKey();
        using var forger = NewKey();
        var forged = await agent.EnrollAsync(new FakeAgent.EnrollOptions { PublicKey = third, PreviousKey = forger });
        Refused(forged, HttpStatusCode.Conflict, ProblemCodes.IdentityConflict);
        Assert.Equal(agent.Thumbprint(newKey), (await _host.DeviceAsync(deviceId)).KeyThumbprint);
    }

    [Fact]
    [Invariant("INV-099")]
    public async Task Inv099_a_session_for_an_unknown_device_is_device_unknown()
    {
        var agent = await _host.EnrolledAsync();
        var unknown = Guid.NewGuid();
        Refused(await agent.SessionAsync(deviceId: unknown), HttpStatusCode.Unauthorized, ProblemCodes.DeviceUnknown);
    }

    [Fact]
    [Invariant("INV-100")]
    public async Task Inv100_the_session_signature_is_checked_with_the_key_of_the_device()
    {
        var first = await _host.EnrolledAsync("PC-ANNE");
        var second = await _host.EnrolledAsync("PC-OLA");
        var forged = await first.SessionAsync(signingKey: second.Key);
        Refused(forged, HttpStatusCode.Unauthorized, ProblemCodes.ChallengeInvalid);
    }

    [Fact]
    [Invariant("INV-101")]
    public async Task Inv101_a_token_works_until_its_expiry_and_only_for_its_device()
    {
        var agent = await _host.EnrolledAsync();
        Assert.Equal(HttpStatusCode.OK, (await agent.CheckInAsync()).Status);
        _host.Clock.Set(_host.Clock.GetUtcNow().AddMinutes(61));
        Refused(await agent.CheckInAsync(), HttpStatusCode.Unauthorized, ProblemCodes.SessionInvalid);
        Refused(await agent.CheckInAsync(token: "A" + new string('B', 42)), HttpStatusCode.Unauthorized, ProblemCodes.SessionInvalid);
    }

    [Fact]
    [Invariant("INV-102")]
    public async Task Inv102_a_revocation_stops_a_valid_token_at_the_next_request()
    {
        var agent = await _host.EnrolledAsync();
        Assert.Equal(HttpStatusCode.OK, (await agent.SubmitAsync(agent.Batch())).Status);
        Assert.Equal(HttpStatusCode.NoContent,
            (await _host.Admin.PostAsync($"/api/v1/organizations/{_host.Org}/devices/{agent.DeviceId}/revoke", new { })).Status);
        Refused(await agent.SubmitAsync(agent.Batch()), HttpStatusCode.Unauthorized, ProblemCodes.DeviceRevoked);
        Refused(await agent.CheckInAsync(), HttpStatusCode.Unauthorized, ProblemCodes.DeviceRevoked);
    }

    [Fact]
    [Invariant("INV-115")]
    public async Task Inv115_the_configuration_has_the_form_of_the_schema_version_the_agent_named()
    {
        var agent = await _host.EnrolledAsync();
        var known = await agent.CheckInAsync(b => { b["configSchemaVersion"] = 1; return b; });
        Assert.Equal(1, known.Body.GetProperty("configSchemaVersion").GetInt32());
        // A newer version than the server knows gets the form of its largest one; no field of a later version appears.
        var newer = await agent.CheckInAsync(b => { b["configSchemaVersion"] = 7; return b; });
        Assert.Equal(1, newer.Body.GetProperty("configSchemaVersion").GetInt32());
        Assert.Empty(Schemas.ValidateComponent("Configuration", newer.Body));
    }

    private static readonly ContractSchemas Schemas = new();

    [Fact]
    [Invariant("INV-117")]
    public async Task Inv117_a_batch_with_content_encoding_or_another_media_type_is_refused_before_parsing()
    {
        var agent = await _host.EnrolledAsync();
        var batch = agent.Batch();
        var scan = batch["scanId"]!.GetValue<string>();
        var bytes = Encoding.UTF8.GetBytes(batch.ToJsonString());
        Refused(await agent.SubmitRawAsync(bytes, scan, configure: r => r.Content!.Headers.ContentEncoding.Add("gzip")),
            HttpStatusCode.UnsupportedMediaType, ProblemCodes.UnsupportedMediaType);
        Refused(await agent.SubmitRawAsync(bytes, scan, contentType: "text/plain"), HttpStatusCode.UnsupportedMediaType,
            ProblemCodes.UnsupportedMediaType);
        Assert.Equal(0, await CountAsync(db => db.ScanBatches));
    }

    [Fact]
    [Invariant("INV-118")]
    public async Task Inv118_a_batch_over_262144_bytes_is_refused_before_parsing()
    {
        var agent = await _host.EnrolledAsync();
        var big = new byte[300 * 1024];
        Array.Fill(big, (byte)'x');
        Refused(await agent.SubmitRawAsync(big, Guid.NewGuid().ToString()), HttpStatusCode.RequestEntityTooLarge, ProblemCodes.PayloadTooLarge);
    }

    [Fact]
    [Invariant("INV-119")]
    public async Task Inv119_a_truncated_body_is_invalid_json_before_the_schema_is_checked()
    {
        var agent = await _host.EnrolledAsync();
        var text = agent.Batch().ToJsonString();
        var reply = await agent.SubmitRawAsync(Encoding.UTF8.GetBytes(text[..(text.Length / 2)]), Guid.NewGuid().ToString());
        Refused(reply, HttpStatusCode.BadRequest, ProblemCodes.InvalidJson);
    }

    [Fact]
    [Invariant("INV-120")]
    public async Task Inv120_an_unknown_schema_version_comes_after_the_version_of_the_agent()
    {
        var agent = await _host.EnrolledAsync();
        Refused(await agent.SubmitAsync(agent.Batch(edit: b => b["schemaVersion"] = "1.0")), HttpStatusCode.UnprocessableEntity,
            ProblemCodes.UnsupportedSchemaVersion);
        // With a version below the minimum the agent is stopped first, so it keeps its buffer.
        var both = await agent.SubmitAsync(agent.Batch(edit: b => { b["schemaVersion"] = "1.0"; b["agentVersion"] = "0.0.9"; }));
        Refused(both, HttpStatusCode.UnprocessableEntity, ProblemCodes.AgentVersionUnsupported);
    }

    [Fact]
    [Invariant("INV-122")]
    public async Task Inv122_free_bytes_over_total_bytes_reject_the_batch()
    {
        var agent = await _host.EnrolledAsync();
        var batch = agent.Batch(edit: b => FakeAgent.ObservationOf(b, "WIN-001")["evidence"] =
            new JsonObject { ["totalBytes"] = 100, ["freeBytes"] = 101 });
        Refused(await agent.SubmitAsync(batch), HttpStatusCode.UnprocessableEntity, ProblemCodes.SchemaViolation);
        Assert.Equal(0, await CountAsync(db => db.ScanBatches));
    }

    [Fact]
    [Invariant("INV-123")]
    public async Task Inv123_an_agent_below_the_minimum_version_sends_no_batches()
    {
        var agent = await _host.EnrolledAsync();
        var reply = await agent.SubmitAsync(agent.Batch(edit: b => b["agentVersion"] = "0.0.9"));
        Refused(reply, HttpStatusCode.UnprocessableEntity, ProblemCodes.AgentVersionUnsupported);
        Assert.Equal("0.1.0", reply.Body.GetProperty("minimumAgentVersion").GetString());
        Assert.Equal(0, await CountAsync(db => db.ScanBatches));
    }

    [Fact]
    [Invariant("INV-124")]
    public async Task Inv124_concurrent_repeats_of_one_scan_id_have_one_effect()
    {
        var agent = await _host.EnrolledAsync();
        var batch = agent.Batch();
        var replies = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => agent.SubmitAsync(batch)));
        Assert.All(replies, r => Assert.Equal(HttpStatusCode.OK, r.Status));
        Assert.Equal(1, replies.Count(r => !r.Body.GetProperty("duplicate").GetBoolean()));
        Assert.Equal(1, await CountAsync(db => db.ScanBatches));
        Assert.Equal(11, await CountAsync(db => db.Observations.Where(o => o.Source == "agent")));
    }

    [Fact]
    [Invariant("INV-126")]
    public async Task Inv126_a_repeat_after_a_pause_gets_the_first_receipt_and_the_clock_is_judged_by_its_own_attempt()
    {
        var agent = await _host.EnrolledAsync();
        var completed = _host.Clock.GetUtcNow().AddMinutes(-20);
        var batch = agent.Batch(completed);
        // 503s and backoff took 20 minutes: the attempt that gets through carries the current time of the PC.
        var first = await agent.SubmitAsync(batch, sentAt: _host.Clock.GetUtcNow());
        Assert.False(first.Body.GetProperty("clockInconsistent").GetBoolean());
        _host.Clock.Set(_host.Clock.GetUtcNow().AddMinutes(20));
        var repeat = await agent.SubmitAsync(batch, sentAt: _host.Clock.GetUtcNow());
        Assert.Equal(HttpStatusCode.OK, repeat.Status);
        Assert.True(repeat.Body.GetProperty("duplicate").GetBoolean());
        Assert.Equal(first.Body.GetProperty("acceptedAt").GetString(), repeat.Body.GetProperty("acceptedAt").GetString());
        Assert.False(repeat.Body.GetProperty("clockInconsistent").GetBoolean());
    }

    [Fact]
    [Invariant("INV-127")]
    public async Task Inv127_the_same_bytes_with_the_same_scan_id_return_the_first_receipt()
    {
        var agent = await _host.EnrolledAsync();
        var batch = agent.Batch();
        var first = await agent.SubmitAsync(batch);
        var repeat = await agent.SubmitAsync(batch);
        Assert.False(first.Body.GetProperty("duplicate").GetBoolean());
        Assert.True(repeat.Body.GetProperty("duplicate").GetBoolean());
        Assert.Equal(first.Body.GetProperty("sequence").GetInt64(), repeat.Body.GetProperty("sequence").GetInt64());
        Assert.Equal(1, await CountAsync(db => db.ScanBatches));
        Assert.Equal(1, (await _host.DeviceAsync(agent.DeviceId!.Value)).LastAcceptedSequence);
    }

    [Fact]
    [Invariant("INV-128")]
    public async Task Inv128_the_same_scan_id_with_other_content_is_a_conflict()
    {
        var agent = await _host.EnrolledAsync();
        var batch = agent.Batch();
        Assert.Equal(HttpStatusCode.OK, (await agent.SubmitAsync(batch)).Status);
        FakeAgent.ObservationOf(batch, "WIN-001")["evidence"]!["freeBytes"] = 1;
        Refused(await agent.SubmitAsync(batch), HttpStatusCode.Conflict, ProblemCodes.IdempotencyConflict);
    }

    [Fact]
    [Invariant("INV-129")]
    public async Task Inv129_a_fingerprint_of_another_machine_is_refused_and_marks_the_device()
    {
        var agent = await _host.EnrolledAsync();
        var other = FakeAgent.ComputeFingerprint(agent.InstallationId, "4C4C4544-0042-3510-8058-B4C04F4E3732", "FFFFFFFF-0000-4000-8000-000000000001");
        Refused(await agent.SubmitAsync(agent.Batch(edit: b => b["machineFingerprint"] = other)), HttpStatusCode.Conflict,
            ProblemCodes.IdentityConflict);
        Assert.Equal("identity_conflict", (await _host.DeviceAsync(agent.DeviceId!.Value)).IdentityState);
        Refused(await agent.CheckInAsync(b => { b["machineFingerprint"] = other; return b; }), HttpStatusCode.Conflict,
            ProblemCodes.IdentityConflict);
        Assert.Equal(0, await CountAsync(db => db.ScanBatches));
    }

    [Fact]
    [Invariant("INV-130")]
    public async Task Inv130_inconsistent_times_of_a_batch_reject_it()
    {
        var agent = await _host.EnrolledAsync();
        var observedLate = agent.Batch(edit: b => FakeAgent.ObservationOf(b, "WIN-004")["observedAt"] =
            FakeAgent.Time(_host.Clock.GetUtcNow().AddMinutes(1)));
        Refused(await agent.SubmitAsync(observedLate), HttpStatusCode.UnprocessableEntity, ProblemCodes.BatchTimeInconsistent);
        var backwards = agent.Batch(edit: b => b["startedAt"] = FakeAgent.Time(_host.Clock.GetUtcNow().AddMinutes(5)));
        Refused(await agent.SubmitAsync(backwards), HttpStatusCode.UnprocessableEntity, ProblemCodes.BatchTimeInconsistent);
    }

    [Fact]
    [Invariant("INV-131")]
    public async Task Inv131_a_batch_older_than_the_limit_by_the_clock_of_the_pc_is_refused()
    {
        var agent = await _host.EnrolledAsync();
        var old = agent.Batch(_host.Clock.GetUtcNow().AddDays(-10));
        Refused(await agent.SubmitAsync(old), HttpStatusCode.UnprocessableEntity, ProblemCodes.BatchTooOld);
        // The age is judged by the clock of the PC: a PC that is three days slow sends a fresh batch of its own time.
        var slow = agent.Batch(_host.Clock.GetUtcNow().AddDays(-3));
        var accepted = await agent.SubmitAsync(slow, sentAt: _host.Clock.GetUtcNow().AddDays(-3));
        Assert.Equal(HttpStatusCode.OK, accepted.Status);
    }

    [Fact]
    [Invariant("INV-132")]
    public async Task Inv132_a_policy_version_above_the_current_or_without_a_revision_is_refused()
    {
        var agent = await _host.EnrolledAsync();
        Refused(await agent.SubmitAsync(agent.Batch(policyVersion: 9)), HttpStatusCode.UnprocessableEntity, ProblemCodes.UnknownPolicyVersion);
        Assert.Equal(HttpStatusCode.Created, (await _host.NewPolicyAsync(p => p["agent"]!["scanIntervalHours"] = 12)).Status);
        Assert.Equal(HttpStatusCode.Created, (await _host.NewPolicyAsync(p => p["agent"]!["scanIntervalHours"] = 8)).Status);
        // Revision 2 is lost, as after a restore of the database to an earlier point.
        await _host.ReadAsync(async scope =>
        {
            await scope.Db.PolicyRevisions.Where(r => r.Version == 2).ExecuteDeleteAsync(Ct);
            await scope.CommitAsync(Ct);
            return 0;
        });
        Refused(await agent.SubmitAsync(agent.Batch(policyVersion: 2)), HttpStatusCode.UnprocessableEntity, ProblemCodes.UnknownPolicyVersion);
        Assert.Equal(HttpStatusCode.OK, (await agent.SubmitAsync(agent.Batch(policyVersion: 3))).Status);
    }

    [Fact]
    [Invariant("INV-133")]
    public async Task Inv133_a_repeated_observation_key_rejects_the_batch()
    {
        var agent = await _host.EnrolledAsync();
        var batch = agent.Batch(edit: b => b["observations"]!.AsArray().Add(FakeAgent.ObservationOf(b, "WIN-005").DeepClone()));
        Refused(await agent.SubmitAsync(batch), HttpStatusCode.UnprocessableEntity, ProblemCodes.DuplicateObservation);
        Assert.Equal(0, await CountAsync(db => db.ScanBatches));
    }

    [Fact]
    [Invariant("INV-134")]
    public async Task Inv134_an_inactive_check_or_a_subject_of_the_wrong_type_rejects_the_batch()
    {
        var agent = await _host.EnrolledAsync();
        var wrongSubject = agent.Batch(edit: b => FakeAgent.ObservationOf(b, "WIN-003")["subject"] = new JsonObject
        {
            ["type"] = "volume", ["volumeId"] = FakeAgent.Volume, ["mountPoint"] = "C:", ["role"] = "os",
        });
        Refused(await agent.SubmitAsync(wrongSubject), HttpStatusCode.UnprocessableEntity, ProblemCodes.UnexpectedSubject);

        // WIN-006 leaves the active checks in revision 2; a batch of that revision that still carries it is refused.
        Assert.Equal(HttpStatusCode.Created, (await _host.NewPolicyAsync(p =>
        {
            var active = p["activeCheckIds"]!.AsArray();
            active.Remove(active.Single(i => i!.GetValue<string>() == "WIN-006"));
        })).Status);
        Refused(await agent.SubmitAsync(agent.Batch(policyVersion: 2)), HttpStatusCode.UnprocessableEntity, ProblemCodes.UnexpectedSubject);
        Assert.Equal(HttpStatusCode.OK, (await agent.SubmitAsync(agent.Batch(policyVersion: 1))).Status);
    }

    [Fact]
    [Invariant("INV-135")]
    public async Task Inv135_a_sequence_not_above_the_last_accepted_one_is_refused_and_logged()
    {
        var agent = await _host.EnrolledAsync();
        Assert.Equal(HttpStatusCode.OK, (await agent.SubmitAsync(agent.Batch(sequence: 5))).Status);
        Refused(await agent.SubmitAsync(agent.Batch(sequence: 5)), HttpStatusCode.Conflict, ProblemCodes.SequenceConflict);
        Refused(await agent.SubmitAsync(agent.Batch(sequence: 3)), HttpStatusCode.Conflict, ProblemCodes.SequenceConflict);
        Assert.NotEmpty(await _host.AuditAsync("device.sequence_resync"));
        var config = await agent.CheckInAsync();
        Assert.Equal(5, config.Body.GetProperty("lastAcceptedSequence").GetInt64());
        Assert.Equal(HttpStatusCode.OK, (await agent.SubmitAsync(agent.Batch(sequence: 6))).Status);
    }

    [Fact]
    [Invariant("INV-197")]
    public async Task Inv197_a_new_key_without_the_signature_of_the_old_one_does_not_replace_it()
    {
        var original = await _host.EnrolledAsync();
        var before = (await _host.DeviceAsync(original.DeviceId!.Value)).KeyThumbprint;
        // A clone with a copy of the disk, the organization key and a key of its own.
        using var clone = new FakeAgent(_host.Factory, _host.KeySecret, original.InstallationId);
        var reply = await clone.EnrollAsync();
        Refused(reply, HttpStatusCode.Conflict, ProblemCodes.IdentityConflict);
        Assert.Contains("key", reply.Detail);
        var device = await _host.DeviceAsync(original.DeviceId!.Value);
        Assert.Equal(before, device.KeyThumbprint);
        Assert.Equal("key", device.ConflictKind);
        Assert.Equal(HttpStatusCode.OK, (await original.CheckInAsync()).Status);
    }

    [Fact]
    [Invariant("INV-198")]
    public async Task Inv198_a_replaced_key_ends_the_sessions_of_the_device()
    {
        var agent = await _host.EnrolledAsync();
        var deviceId = agent.DeviceId!.Value;
        var oldToken = agent.Token!;
        using var cleared = new FakeAgent(_host.Factory, _host.KeySecret, agent.InstallationId);
        Refused(await cleared.EnrollAsync(), HttpStatusCode.Conflict, ProblemCodes.IdentityConflict);
        var resolved = await _host.Admin.PostAsync($"/api/v1/organizations/{_host.Org}/devices/{deviceId}/identity-resolutions",
            new { decision = "accept_new_key" }, "Device");
        Assert.Equal(HttpStatusCode.OK, resolved.Status);
        Refused(await agent.SubmitAsync(agent.Batch(), token: oldToken), HttpStatusCode.Unauthorized, ProblemCodes.SessionInvalid);
        Assert.Equal(2, (await _host.AuditAsync("device.identity_resolved")).Count + (await _host.AuditAsync("device.key_replaced")).Count);
        cleared.DeviceId = deviceId;
        Assert.Equal(HttpStatusCode.Created, (await cleared.SessionAsync()).Status);
    }
}
