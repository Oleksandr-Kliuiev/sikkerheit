using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Sikkerheit.Agent.Api;
using Sikkerheit.Agent.Collectors;
using Sikkerheit.Agent.Collectors.Runtime;
using Sikkerheit.Agent.Config;
using Sikkerheit.Agent.Keys;
using Sikkerheit.Agent.Protocol;
using Sikkerheit.Agent.Scan;
using Sikkerheit.Agent.Storage;

namespace Sikkerheit.Agent.Runtime;

/// <summary>Everything the engine uses; the Windows parts are behind interfaces, so the engine runs the same on any OS.</summary>
public sealed record AgentServices(
    AgentPaths Paths,
    AgentStateStore State,
    BatchBuffer Buffer,
    AgentApiClient Api,
    IDeviceKeyStore Keys,
    ISecretProtector Protector,
    IMachineIdentityReader Identity,
    IOsVolumeResolver OsVolume,
    IReadOnlyList<ICollector> Collectors,
    CollectorRunner Runner,
    CollectorLimits Limits,
    ScanBatchBuilder Builder,
    ConfigurationParser Configurations,
    ISystemProbe Probe,
    TimeProvider Time,
    string AgentVersion);

/// <summary>
/// The agent as a sequence of steps: each step does the work that is due in the current state of the automaton (05). The step does not
/// sleep: the worker of the service calls it in a loop, the tests call it with a manual clock.
/// </summary>
public sealed partial class AgentEngine
{
    private readonly AgentServices _s;
    private readonly ILogger<AgentEngine> _log;
    private readonly Random _random;
    private AgentPosition _position;
    private AgentConfiguration? _configuration;
    private string? _token;
    private DateTimeOffset _tokenExpires;
    private string? _fingerprint;
    private bool _enrollNow = true;
    private bool _refreshConfiguration;
    private bool _checkInPassedSinceServerError = true;
    private int _challengeFailures;
    private int _jitterMinutes;
    private DateTimeOffset _lastKeyPoll = DateTimeOffset.MinValue;
    private string? _pendingScanRequestId;

    public AgentEngine(AgentServices services, ILogger<AgentEngine> log, Random? random = null)
    {
        _s = services;
        _log = log;
        _random = random ?? Random.Shared;
    }

    public AgentState State => _position.State;

    public AgentConfiguration? Configuration => _configuration;

    public string? DeviceId => _s.State.Get(StateKeys.DeviceId);

    public BatchBuffer Buffer => _s.Buffer;

    /// <summary>Three abandoned collectors: the service ends with an error and SCM restarts it by the recovery actions (02).</summary>
    public bool ShouldExit => _s.Runner.AbandonedCount >= CollectorRunner.AbandonedLimit;

    private DateTimeOffset Now => _s.Time.GetUtcNow();

    /// <summary>Start of the service: counters of the telemetry, a crash of the previous run, restoring of the state.</summary>
    public void Initialize()
    {
        var state = _s.State;
        state.Increment(StateKeys.ServiceStarts);
        if (state.GetBool(StateKeys.Running))
        {
            state.SetTime(StateKeys.LastCrashAt, state.GetTime(StateKeys.LastAliveAt) ?? Now);
        }
        state.SetBool(StateKeys.Running, true);
        state.SetTime(StateKeys.LastAliveAt, Now);
        _position = new AgentPosition(
            Enum.TryParse<AgentState>(state.Get(StateKeys.State), out var saved) ? saved : AgentState.Unenrolled,
            Enum.TryParse<AgentState>(state.Get(StateKeys.BackoffReturn), out var back) ? back : null);
        var json = state.Get(StateKeys.Configuration);
        if (json is not null)
        {
            using var document = JsonDocument.Parse(json);
            if (_s.Configurations.TryParse(document.RootElement, out var stored, out _))
            {
                _configuration = stored;
            }
        }
        // A new version of the agent from RMM removes the block of the version.
        if (_position.State == AgentState.VersionBlocked && state.Get(StateKeys.BlockedVersion) != _s.AgentVersion)
        {
            Apply(AgentStateMachine.On(_position, AgentEvent.AgentUpgraded));
        }
        _jitterMinutes = NextJitter();
        EnsureInstallationId();
    }

    /// <summary>Clean stop of the service: the next start is not a crash.</summary>
    public void Shutdown() => _s.State.SetBool(StateKeys.Running, false);

    public async Task StepAsync(CancellationToken ct)
    {
        var now = Now;
        _s.State.SetTime(StateKeys.LastAliveAt, now);
        PollKeyFile(now);
        if (_position.State == AgentState.Revoked)
        {
            return;
        }
        if (_position.State == AgentState.Backoff)
        {
            if (now < _s.State.GetTime(StateKeys.BackoffUntil))
            {
                await CollectIfDueAsync(ct).ConfigureAwait(false);
                return;
            }
            Apply(AgentStateMachine.On(_position, AgentEvent.BackoffElapsed));
        }
        await CollectIfDueAsync(ct).ConfigureAwait(false);
        switch (_position.State)
        {
            case AgentState.Unenrolled:
            case AgentState.EnrollmentBlocked:
                if (EnrollmentDue(now))
                {
                    await EnrollAsync(ct).ConfigureAwait(false);
                }
                break;
            case AgentState.Active:
                await RunActiveAsync(ct).ConfigureAwait(false);
                break;
            case AgentState.VersionBlocked:
                await RunVersionBlockedAsync(ct).ConfigureAwait(false);
                break;
            case AgentState.Suspended:
            case AgentState.IdentityConflict:
                await RunDailyAsync(ct).ConfigureAwait(false);
                break;
        }
    }

    // ---- state ----------------------------------------------------------------------------------------------------------------

    private void Apply(AgentPosition next)
    {
        if (next == _position)
        {
            return;
        }
        _log.LogInformation("Agent state {From} -> {To}", _position.State, next.State);
        var previous = _position.State;
        _position = next;
        _s.State.Set(StateKeys.State, next.State.ToString());
        _s.State.Set(StateKeys.BackoffReturn, next.BackoffReturn?.ToString());
        if (next.State == AgentState.VersionBlocked)
        {
            _s.State.Set(StateKeys.BlockedVersion, _s.AgentVersion);
        }
        if (next.State is AgentState.Suspended or AgentState.IdentityConflict or AgentState.VersionBlocked && previous != next.State)
        {
            _s.State.SetTime(StateKeys.LastStateAttemptAt, Now);
        }
        if (next.State == AgentState.Unenrolled && previous != AgentState.Unenrolled)
        {
            _enrollNow = true;
        }
        if (next.State == AgentState.Revoked)
        {
            CleanUpRevoked();
        }
    }

    /// <summary>Reaction to a failed answer: the automaton, the pause of Backoff, the loss of the session or of the device.</summary>
    private void ApplyFailure(ApiResult result)
    {
        var actions = result.Actions;
        var next = AgentStateMachine.OnFailure(_position, actions, result.Operation, result.ProblemCode);
        if (actions.HasFlag(AgentActions.RenewSession))
        {
            _token = null;
        }
        if (result.ProblemCode == "device_unknown")
        {
            _token = null;
            _s.State.Set(StateKeys.DeviceId, null);
        }
        if (next.State == AgentState.Backoff && _position.State != AgentState.Backoff)
        {
            EnterBackoff(result);
        }
        Apply(next);
        if (result.Transport is not null)
        {
            _log.LogWarning(result.Transport, "{Operation}: transport error", result.Operation);
        }
        else
        {
            _log.LogWarning("{Operation}: {Status} {Code}", result.Operation, result.Status, result.ProblemCode ?? "(no Problem)");
        }
    }

    private void EnterBackoff(ApiResult result)
    {
        // The pause grows with consecutive failures of the same operation; a success of another operation does not reset it.
        if (_s.State.Get(StateKeys.BackoffOperation) != result.Operation.ToString())
        {
            _s.State.Set(StateKeys.BackoffFailures, "0");
            _s.State.Set(StateKeys.BackoffOperation, result.Operation.ToString());
        }
        var failures = (int)_s.State.Increment(StateKeys.BackoffFailures);
        TimeSpan delay;
        if (result.Actions.HasFlag(AgentActions.RetryAfter) && result.RetryAfter is { } wait)
        {
            delay = wait;
        }
        else
        {
            var exponential = AgentLimits.BackoffMin * Math.Pow(2, Math.Min(failures - 1, 10));
            var capped = exponential > AgentLimits.BackoffMax ? AgentLimits.BackoffMax : exponential;
            delay = capped * (0.8 + (_random.NextDouble() * 0.4));
        }
        _s.State.SetTime(StateKeys.BackoffUntil, Now + delay);
    }

    private void ResetBackoff(AgentOperation operation)
    {
        if (_s.State.Get(StateKeys.BackoffOperation) == operation.ToString())
        {
            _s.State.Set(StateKeys.BackoffFailures, "0");
        }
    }

    private void CleanUpRevoked()
    {
        // device_revoked: the key, the session and the buffer are deleted, there are no further requests (04).
        _s.Keys.Delete();
        _s.Buffer.Clear();
        _token = null;
        _s.State.Set(StateKeys.DeviceId, null);
        _s.State.Set(StateKeys.Configuration, null);
        _s.State.Set(StateKeys.PendingEnrollment, null);
        _configuration = null;
        _log.LogWarning("The device is revoked: the key and the buffer are deleted; reinstallation is required");
    }

    // ---- registration key file and identity -------------------------------------------------------------------------------------

    private void EnsureInstallationId()
    {
        if (!File.Exists(_s.Paths.InstallationIdFile))
        {
            Directory.CreateDirectory(_s.Paths.DataDirectory);
            File.WriteAllText(_s.Paths.InstallationIdFile, Guid.NewGuid().ToString("D"));
        }
    }

    private Guid InstallationId() => Guid.Parse(File.ReadAllText(_s.Paths.InstallationIdFile).Trim());

    private string Fingerprint()
    {
        if (_fingerprint is not null)
        {
            return _fingerprint;
        }
        var raw = _s.Identity.Read();
        return _fingerprint = MachineFingerprint.Compute(InstallationId(), raw.ProductUuid, raw.MachineGuid);
    }

    private void PollKeyFile(DateTimeOffset now)
    {
        if (now - _lastKeyPoll < AgentLimits.KeyFilePoll)
        {
            return;
        }
        _lastKeyPoll = now;
        var incoming = _s.Paths.IncomingKeyFile;
        if (!File.Exists(incoming))
        {
            return;
        }
        string key;
        try
        {
            key = File.ReadAllText(incoming, Encoding.UTF8).Trim();
        }
        catch (IOException exception)
        {
            _log.LogWarning(exception, "The key file cannot be read yet");
            return;
        }
        var valid = EnrollmentKeyFormat.IsValid(key);
        if (valid)
        {
            var temp = _s.Paths.ProtectedKeyFile + ".tmp";
            File.WriteAllBytes(temp, _s.Protector.Protect(Encoding.UTF8.GetBytes(key)));
            File.Move(temp, _s.Paths.ProtectedKeyFile, overwrite: true);
        }
        File.Delete(incoming); // the plain key never stays on the disk, even if the format is wrong
        if (!valid)
        {
            _log.LogWarning("The key file has an invalid format and was deleted");
            return;
        }
        _log.LogInformation("A registration key was saved under DPAPI and the file was deleted");
        _enrollNow = true;
        _s.State.Set(StateKeys.LastEnrollAttemptAt, null);
        Apply(AgentStateMachine.On(_position, AgentEvent.EnrollmentKeyFileFound));
    }

    private string? LoadEnrollmentKey()
    {
        if (!File.Exists(_s.Paths.ProtectedKeyFile))
        {
            return null;
        }
        try
        {
            return Encoding.UTF8.GetString(_s.Protector.Unprotect(File.ReadAllBytes(_s.Paths.ProtectedKeyFile)));
        }
        catch (Exception exception) when (exception is IOException or System.Security.Cryptography.CryptographicException)
        {
            _log.LogError(exception, "The stored registration key cannot be read");
            return null;
        }
    }

    // ---- registration -----------------------------------------------------------------------------------------------------------

    private bool EnrollmentDue(DateTimeOffset now)
    {
        if (_enrollNow)
        {
            return true;
        }
        var last = _s.State.GetTime(StateKeys.LastEnrollAttemptAt);
        return last is null || now - last >= AgentLimits.DailyAttempt;
    }

    /// <summary>Registration with the stored organization key (05, "enrollAgent"). A retry after a lost answer sends the same bytes.</summary>
    private async Task EnrollAsync(CancellationToken ct)
    {
        var key = LoadEnrollmentKey();
        if (key is null)
        {
            _enrollNow = false;
            _s.State.SetTime(StateKeys.LastEnrollAttemptAt, Now);
            Apply(AgentStateMachine.On(_position, AgentEvent.EnrollmentKeyMissing));
            return;
        }
        var body = await PrepareEnrollmentAsync(ct).ConfigureAwait(false);
        if (body is null)
        {
            return;
        }
        var result = await _s.Api.EnrollAsync(body, key, ct).ConfigureAwait(false);
        if (result.IsSuccess && result.Body is { } json && _s.Api.Matches("Enrollment", json))
        {
            _s.State.Set(StateKeys.DeviceId, json.GetProperty("deviceId").GetString());
            _s.State.Set(StateKeys.PendingEnrollment, null);
            _s.State.Set(StateKeys.LastEnrollAttemptAt, null);
            _enrollNow = false;
            _challengeFailures = 0;
            _token = null;
            _refreshConfiguration = true;
            ResetBackoff(AgentOperation.Enroll);
            Apply(AgentStateMachine.On(_position, AgentEvent.Enrolled));
            return;
        }
        if (result.IsSuccess)
        {
            _log.LogWarning("The answer of enrollAgent does not match the Enrollment schema");
            ApplyFailure(result with { Status = 0, Transport = new InvalidDataException("Enrollment schema") });
            return;
        }
        AfterEnrollFailure(result);
    }

    private void AfterEnrollFailure(ApiResult result)
    {
        var actions = result.Actions;
        var retry = actions.HasFlag(AgentActions.RetryAfter) || actions.HasFlag(AgentActions.RetryBackoff);
        if (actions.HasFlag(AgentActions.NewChallenge))
        {
            // One repeat with a new nonce, then retry_backoff.
            _s.State.Set(StateKeys.PendingEnrollment, null);
            if (++_challengeFailures >= 2)
            {
                _challengeFailures = 0;
                ApplyFailure(result with { ProblemCode = null });
            }
            return;
        }
        if (actions.HasFlag(AgentActions.Reenroll))
        {
            // idempotency_conflict: a new registrationRequestId on the next step.
            _s.State.Set(StateKeys.PendingEnrollment, null);
            return;
        }
        if (!retry)
        {
            // A definitive answer: the stored request is useless, the next attempt is a day later (skip_request).
            _s.State.Set(StateKeys.PendingEnrollment, null);
            _enrollNow = false;
            _s.State.SetTime(StateKeys.LastEnrollAttemptAt, Now);
        }
        ApplyFailure(result);
    }

    /// <summary>The request stored for 24 hours is repeated as is; otherwise a challenge is requested and a new request is signed.</summary>
    private async Task<byte[]?> PrepareEnrollmentAsync(CancellationToken ct)
    {
        var pending = _s.State.Get(StateKeys.PendingEnrollment);
        var created = _s.State.GetTime(StateKeys.PendingEnrollmentAt);
        if (pending is not null && created is not null && Now - created < AgentLimits.EnrollmentRetention)
        {
            return Convert.FromBase64String(pending);
        }
        var challenge = await _s.Api.CreateChallengeAsync("enroll", null, ct).ConfigureAwait(false);
        if (!challenge.IsSuccess || challenge.Body is not { } nonceBody || !_s.Api.Matches("Challenge", nonceBody))
        {
            ApplyFailure(challenge.IsSuccess ? challenge with { Status = 0, Transport = new InvalidDataException("Challenge schema") } : challenge);
            return null;
        }
        string fingerprint;
        try
        {
            fingerprint = Fingerprint();
        }
        catch (Exception exception)
        {
            _log.LogError(exception, "The machine fingerprint cannot be computed");
            ApplyFailure(new ApiResult(AgentOperation.Enroll, 0, null, null, null, null, exception));
            return null;
        }
        using var deviceKey = _s.Keys.Open() ?? _s.Keys.Create();
        var nonce = nonceBody.GetProperty("nonce").GetString()!;
        var requestId = Guid.NewGuid().ToString("D");
        var installationId = InstallationId().ToString("D");
        var signature = deviceKey.Sign(SignedStrings.Enroll(nonce, requestId, installationId, fingerprint, deviceKey.KeyProtection, deviceKey.PublicKey));
        var request = new JsonObject
        {
            ["registrationRequestId"] = requestId,
            ["installationId"] = installationId,
            ["displayName"] = DisplayName(),
            ["machineFingerprint"] = fingerprint,
            ["publicKey"] = new JsonObject { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = deviceKey.PublicKey.X, ["y"] = deviceKey.PublicKey.Y },
            ["keyProtection"] = deviceKey.KeyProtection,
            ["nonce"] = nonce,
            ["signature"] = Base64Url.Encode(signature),
        };
        var bytes = Encoding.UTF8.GetBytes(request.ToJsonString());
        _s.State.Set(StateKeys.PendingEnrollment, Convert.ToBase64String(bytes));
        _s.State.SetTime(StateKeys.PendingEnrollmentAt, Now);
        _s.State.Set(StateKeys.KeyProtection, deviceKey.KeyProtection);
        return bytes;
    }

    private string DisplayName()
    {
        var name = new string(_s.Probe.MachineName.Where(c => !char.IsControl(c) && c is not ('<' or '>')).ToArray()).Trim();
        return name.Length == 0 ? "unknown" : name.Length > 120 ? name[..120] : name;
    }

    // ---- session ----------------------------------------------------------------------------------------------------------------

    /// <summary>Session by challenge-response (04). False: the token cannot be obtained now, the automaton already knows why.</summary>
    private async Task<bool> EnsureSessionAsync(CancellationToken ct)
    {
        if (_token is not null && _tokenExpires - Now > AgentLimits.SessionMargin)
        {
            return true;
        }
        var deviceId = DeviceId;
        if (deviceId is null)
        {
            Apply(new AgentPosition(AgentState.Unenrolled));
            return false;
        }
        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var deviceKey = _s.Keys.Open();
            if (deviceKey is null)
            {
                // The key is lost (the TPM is cleared): register again with a new key and the same installationId.
                _log.LogWarning("The device key is missing, registration again");
                ReenrollSameInstallation();
                return false;
            }
            var challenge = await _s.Api.CreateChallengeAsync("session", deviceId, ct).ConfigureAwait(false);
            if (!challenge.IsSuccess || challenge.Body is not { } nonceBody || !_s.Api.Matches("Challenge", nonceBody))
            {
                ApplyFailure(challenge.IsSuccess ? challenge with { Status = 0, Transport = new InvalidDataException("Challenge schema") } : challenge);
                return false;
            }
            var nonce = nonceBody.GetProperty("nonce").GetString()!;
            var signature = Base64Url.Encode(deviceKey.Sign(SignedStrings.Session(nonce, deviceId)));
            var session = await _s.Api.CreateSessionAsync(deviceId, nonce, signature, ct).ConfigureAwait(false);
            if (session.IsSuccess && session.Body is { } body && _s.Api.Matches("AgentSession", body))
            {
                _token = body.GetProperty("accessToken").GetString();
                _tokenExpires = DateTimeOffset.Parse(body.GetProperty("expiresAt").GetString()!, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
                _challengeFailures = 0;
                ResetBackoff(AgentOperation.CreateSession);
                ResetBackoff(AgentOperation.CreateChallenge);
                return true;
            }
            if (session.Actions.HasFlag(AgentActions.NewChallenge))
            {
                // One repeat with a new nonce; the second refusal in a row leads to registration again (05).
                continue;
            }
            ApplyFailure(session.IsSuccess ? session with { Status = 0, Transport = new InvalidDataException("AgentSession schema") } : session);
            return false;
        }
        ReenrollSameInstallation();
        return false;
    }

    /// <summary>
    /// The second challenge_invalid in a row with a local key, or no local key: registration again with the same installationId,
    /// not more than once per day. If the server remembers another key, it answers identity_conflict of the kind key (05, INV-106).
    /// </summary>
    private void ReenrollSameInstallation()
    {
        var now = Now;
        var last = _s.State.GetTime(StateKeys.LastReenrollAt);
        if (last is not null && now - last < AgentLimits.DailyAttempt)
        {
            EnterBackoff(new ApiResult(AgentOperation.CreateSession, 0, null, null, null, null, new InvalidOperationException("reenroll limit")));
            Apply(new AgentPosition(AgentState.Backoff, _position.State));
            return;
        }
        _s.State.SetTime(StateKeys.LastReenrollAt, now);
        _s.State.Set(StateKeys.DeviceId, null);
        _s.State.Set(StateKeys.PendingEnrollment, null);
        _token = null;
        Apply(new AgentPosition(AgentState.Unenrolled));
        _enrollNow = true;
    }
}

/// <summary>Format of the registration key: <c>sikk_</c> and 32 random bytes in base64url (04).</summary>
public static class EnrollmentKeyFormat
{
    public static bool IsValid(string key) =>
        key.Length == 5 + 43 && key.StartsWith("sikk_", StringComparison.Ordinal)
        && key.AsSpan(5).IndexOfAnyExcept("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") < 0;
}
