using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Sikkerheit.Agent.Api;
using Sikkerheit.Agent.Collectors;
using Sikkerheit.Agent.Collectors.Mapping;
using Sikkerheit.Agent.Collectors.Runtime;
using Sikkerheit.Agent.Config;
using Sikkerheit.Agent.Storage;

namespace Sikkerheit.Agent.Runtime;

public sealed partial class AgentEngine
{
    // ---- Active, VersionBlocked, Suspended, IdentityConflict -----------------------------------------------------------------------

    private async Task RunActiveAsync(CancellationToken ct)
    {
        if (CheckInDue(Now) && !await CheckInAsync(ct).ConfigureAwait(false))
        {
            if (_position.State != AgentState.Active)
            {
                return;
            }
        }
        if (_position.State == AgentState.Active)
        {
            await SendBatchesAsync(int.MaxValue, ct).ConfigureAwait(false);
        }
    }

    private bool CheckInDue(DateTimeOffset now)
    {
        if (_refreshConfiguration)
        {
            return true;
        }
        var last = _s.State.GetTime(StateKeys.LastCheckInAt);
        var interval = _configuration is { } c ? TimeSpan.FromHours(c.CheckInIntervalHours) : AgentLimits.DefaultCheckIn;
        return last is null || now - last >= interval;
    }

    /// <summary>VersionBlocked: check-in every 4 hours; when the configuration allows our version, one trial batch.</summary>
    private async Task RunVersionBlockedAsync(CancellationToken ct)
    {
        var last = _s.State.GetTime(StateKeys.LastStateAttemptAt);
        if (last is not null && Now - last < AgentLimits.VersionBlockedCheckIn)
        {
            return;
        }
        _s.State.SetTime(StateKeys.LastStateAttemptAt, Now);
        if (!await CheckInAsync(ct).ConfigureAwait(false) || _position.State != AgentState.VersionBlocked)
        {
            return;
        }
        if (_configuration is { } c && AgentVersion.Compare(c.MinimumAgentVersion, _s.AgentVersion) <= 0)
        {
            await SendBatchesAsync(1, ct, trial: true).ConfigureAwait(false);
        }
    }

    /// <summary>Suspended and IdentityConflict: once a day a check-in, and without deviceId or without a key — registration.</summary>
    private async Task RunDailyAsync(CancellationToken ct)
    {
        var last = _s.State.GetTime(StateKeys.LastStateAttemptAt);
        if (last is not null && Now - last < AgentLimits.DailyAttempt && !_enrollNow)
        {
            return;
        }
        _s.State.SetTime(StateKeys.LastStateAttemptAt, Now);
        using (var key = _s.Keys.Open())
        {
            if (DeviceId is null || key is null)
            {
                await EnrollAsync(ct).ConfigureAwait(false);
                return;
            }
        }
        await CheckInAsync(ct).ConfigureAwait(false);
    }

    // ---- check-in ---------------------------------------------------------------------------------------------------------------

    /// <summary>Check-in with the telemetry (02). True when the server answered 200 with a configuration; a bad configuration is only logged.</summary>
    private async Task<bool> CheckInAsync(CancellationToken ct)
    {
        for (var attempt = 0; attempt < 2; attempt++)
        {
            if (!await EnsureSessionAsync(ct).ConfigureAwait(false))
            {
                return false;
            }
            var reportedRejected = _s.State.GetBool(StateKeys.ConfigRejected);
            var body = BuildCheckIn(reportedRejected);
            var result = await _s.Api.CheckInAsync(body, _token!, ct).ConfigureAwait(false);
            if (result.IsSuccess)
            {
                OnCheckInAnswer(result);
                return true;
            }
            if (result.Actions.HasFlag(AgentActions.RenewSession) && attempt == 0)
            {
                _token = null;
                continue;
            }
            ApplyFailure(result);
            return false;
        }
        return false;
    }

    private JsonObject BuildCheckIn(bool configRejected)
    {
        var state = _s.State;
        var lastCrash = state.GetTime(StateKeys.LastCrashAt);
        var body = new JsonObject
        {
            ["observedAt"] = Iso.Format(Now),
            ["agentVersion"] = _s.AgentVersion,
            ["configSchemaVersion"] = ConfigurationParser.SchemaVersion,
            ["machineFingerprint"] = Fingerprint(),
            ["reportedDisplayName"] = DisplayName(),
            ["queueDepth"] = _s.Buffer.Count,
            ["bufferBytes"] = _s.Buffer.Bytes,
            ["droppedBatchCount"] = _s.Buffer.DroppedBatchCount,
            ["rejectedBatchCount"] = _s.Buffer.RejectedBatchCount,
            ["configRejected"] = configRejected,
            ["serviceStarts"] = state.GetLong(StateKeys.ServiceStarts),
            ["lastCrashAt"] = lastCrash is null ? null : Iso.Format(lastCrash.Value),
            ["workingSetMb"] = _s.Probe.WorkingSetMb,
            ["cpuSeconds"] = _s.Probe.CpuSeconds,
            ["abandonedCollectors"] = _s.Runner.AbandonedCount,
        };
        return body;
    }

    private void OnCheckInAnswer(ApiResult result)
    {
        _s.State.SetTime(StateKeys.LastCheckInAt, Now);
        _refreshConfiguration = false;
        _checkInPassedSinceServerError = true;
        ResetBackoff(AgentOperation.CheckIn);
        var error = "the body is not JSON";
        AgentConfiguration? configuration = null;
        if (result.Body is { } json && _s.Configurations.TryParse(json, out configuration, out error))
        {
            _configuration = configuration;
            _s.State.Set(StateKeys.Configuration, json.GetRawText());
            _s.State.SetBool(StateKeys.ConfigRejected, false);
            AcceptConfiguration(configuration!);
        }
        else
        {
            // The whole configuration is rejected, the previous one stays; the next check-in reports configRejected (INV-116).
            _log.LogWarning("The configuration is rejected: {Error}", error);
            _s.State.SetBool(StateKeys.ConfigRejected, true);
        }
        Apply(AgentStateMachine.On(_position, AgentEvent.CheckInSucceeded));
    }

    private void AcceptConfiguration(AgentConfiguration configuration)
    {
        var drift = (configuration.ServerTime - Now).Duration();
        if (drift > TimeSpan.FromMinutes(5))
        {
            _log.LogWarning("The clock of the PC differs from the server by {Drift}", drift);
        }
        if (configuration.PendingScanRequestId is { } id)
        {
            _pendingScanRequestId = id;
        }
        if (_position.State == AgentState.Active && AgentVersion.Compare(configuration.MinimumAgentVersion, _s.AgentVersion) > 0)
        {
            Apply(new AgentPosition(AgentState.VersionBlocked));
        }
    }

    // ---- sending ----------------------------------------------------------------------------------------------------------------

    /// <summary>Sends batches one by one from the old to the new, waiting for 200 (02).</summary>
    private async Task SendBatchesAsync(int limit, CancellationToken ct, bool trial = false)
    {
        var sent = 0;
        var renewed = 0;
        var resynced = false;
        while (sent < limit && Buffer.Oldest() is { } batch)
        {
            if (!await EnsureSessionAsync(ct).ConfigureAwait(false))
            {
                return;
            }
            var result = await _s.Api.SubmitScanAsync(batch.ScanId, batch.Body, _token!, Now, ct).ConfigureAwait(false);
            if (result.IsSuccess)
            {
                if (result.Body is { } receipt && !_s.Api.Matches("ScanReceipt", receipt))
                {
                    _log.LogWarning("The receipt does not match the ScanReceipt schema; the batch is considered accepted");
                }
                Buffer.Remove(batch.ScanId);
                sent++;
                _checkInPassedSinceServerError = true;
                ResetBackoff(AgentOperation.SubmitScan);
                if (trial)
                {
                    Apply(AgentStateMachine.On(_position, AgentEvent.TrialBatchAccepted));
                }
                continue;
            }
            var actions = result.Actions;
            if (result.Status == 500 && result.ProblemCode is null)
            {
                if (HandleServerError(batch))
                {
                    continue;
                }
                ApplyFailure(result);
                return;
            }
            if (actions.HasFlag(AgentActions.RenewSession) && renewed++ < 2)
            {
                _token = null;
                continue;
            }
            if (actions.HasFlag(AgentActions.DropBatch))
            {
                _log.LogWarning("The batch {ScanId} is rejected by the server ({Code}) and deleted", batch.ScanId, result.ProblemCode);
                Buffer.Reject(batch.ScanId);
                if (actions.HasFlag(AgentActions.RefreshConfiguration) && !await CheckInAsync(ct).ConfigureAwait(false))
                {
                    return;
                }
                continue;
            }
            if (actions.HasFlag(AgentActions.ResyncSequence) && !resynced)
            {
                resynced = true;
                if (!await CheckInAsync(ct).ConfigureAwait(false))
                {
                    return;
                }
                ResyncSequence();
                continue;
            }
            ApplyFailure(result);
            return;
        }
    }

    /// <summary>
    /// Five answers 500 for one batch with a successful check-in between the attempts: the batch is unfit and is deleted like drop_batch,
    /// so the queue does not stop (05). Returns true when the batch was deleted.
    /// </summary>
    private bool HandleServerError(BufferedBatch batch)
    {
        if (!_checkInPassedSinceServerError)
        {
            return false;
        }
        _checkInPassedSinceServerError = false;
        if (Buffer.RecordServerError(batch.ScanId) < AgentLimits.ServerErrorLimit)
        {
            return false;
        }
        _log.LogError("The batch {ScanId} got five answers 500 and is deleted as unfit", batch.ScanId);
        Buffer.Reject(batch.ScanId);
        return true;
    }

    private void ResyncSequence()
    {
        if (_configuration is not { } c)
        {
            return;
        }
        var removed = Buffer.Resequence(c.LastAcceptedSequence, c.LastAcceptedCompletedAt);
        _log.LogWarning("Sequence resync: {Removed} batches were accepted before the checkpoint, the rest is renumbered from {Next}",
            removed, c.LastAcceptedSequence + 1);
    }

    // ---- collection -------------------------------------------------------------------------------------------------------------

    private int NextJitter() => _configuration is { ScanJitterMinutes: > 0 } c ? _random.Next(0, c.ScanJitterMinutes + 1) : 0;

    private bool ScanDue(DateTimeOffset now)
    {
        if (_configuration is not { } c || _s.Runner.AbandonedCount >= CollectorRunner.AbandonedLimit)
        {
            return false;
        }
        if (_pendingScanRequestId is not null)
        {
            return true;
        }
        // A planned collection starts no earlier than 60 minutes after the start of the OS.
        if (now < _s.Probe.BootTime + AgentLimits.BootDelay)
        {
            return false;
        }
        var last = _s.State.GetTime(StateKeys.LastScanAt);
        return last is null || now >= last + TimeSpan.FromHours(c.ScanIntervalHours) + TimeSpan.FromMinutes(_jitterMinutes);
    }

    private async Task CollectIfDueAsync(CancellationToken ct)
    {
        if (!ScanDue(Now))
        {
            return;
        }
        await RunScanAsync(ct).ConfigureAwait(false);
    }

    private async Task RunScanAsync(CancellationToken ct)
    {
        var c = _configuration!;
        var started = Now;
        var volume = _s.OsVolume.Resolve();
        var active = _s.Collectors.Where(x => c.ActiveCheckIds.Contains(x.CheckId)).ToList();
        var items = await _s.Runner.RunAsync(active, new CollectionContext(started, volume, ct), _s.Limits).ConfigureAwait(false);
        var completed = Now;
        string fingerprint;
        try
        {
            fingerprint = Fingerprint();
        }
        catch (Exception exception)
        {
            _log.LogError(exception, "The scan is dropped: the machine fingerprint is unavailable");
            return;
        }
        var requestId = _pendingScanRequestId;
        var sequence = Buffer.NextSequence(c.LastAcceptedSequence);
        var built = _s.Builder.Build(c, items, volume, fingerprint, _s.AgentVersion, sequence, started, completed, requestId);
        _s.State.SetTime(StateKeys.LastScanAt, completed);
        _jitterMinutes = NextJitter();
        _pendingScanRequestId = null;
        if (built is null)
        {
            return;
        }
        Buffer.Enqueue(new BufferedBatch(built.ScanId, built.Sequence, built.CompletedAt, built.Body, 0), c.MaxBufferBytes, c.MaxBufferDays, completed);
    }
}
