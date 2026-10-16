using System.Text.Json.Nodes;

namespace Sikkerheit.Agent.Collectors;

/// <summary>A fact or the reason why it is unavailable (03, "Семантика результата"): a collector never decides applicability.</summary>
public sealed record CollectorOutcome(JsonObject? Evidence, string? ReasonCode)
{
    public bool IsCollected => Evidence is not null;

    public static CollectorOutcome Collected(JsonObject evidence) => new(evidence, null);

    public static CollectorOutcome Unavailable(string reasonCode) => new(null, reasonCode);
}

/// <summary>Reasons of unavailable observations allowed by observation.schema.json.</summary>
public static class ReasonCodes
{
    public const string PermissionDenied = "permission_denied";
    public const string Unsupported = "unsupported";
    public const string CollectorTimeout = "collector_timeout";
    public const string TemporaryError = "temporary_error";
}

/// <summary>A collector stops with a reason defined by the contract.</summary>
public sealed class CollectorException(string reasonCode, string message, Exception? inner = null) : Exception(message, inner)
{
    public string ReasonCode { get; } = reasonCode;
}

/// <summary>Maps an exception of a Windows API call to the reason of the unavailable observation.</summary>
public static class CollectorErrors
{
    public static string Reason(Exception exception) => exception switch
    {
        CollectorException known => known.ReasonCode,
        UnauthorizedAccessException => ReasonCodes.PermissionDenied,
        System.Security.SecurityException => ReasonCodes.PermissionDenied,
        PlatformNotSupportedException or NotSupportedException => ReasonCodes.Unsupported,
        _ => ReasonCodes.TemporaryError,
    };
}

/// <summary>Volume of the operating system: Win32 volume GUID path and the drive letter as an attribute (05, "Субъекты").</summary>
public sealed record VolumeRef(string VolumeId, string? MountPoint);

/// <summary>What a collector receives for one session.</summary>
public sealed record CollectionContext(DateTimeOffset Now, VolumeRef? OsVolume, CancellationToken Cancellation);

/// <summary>Collector of one check WIN-xxx. Runs in its own thread (02, "Выполнение локальной проверки").</summary>
public interface ICollector
{
    string CheckId { get; }

    string CollectorVersion { get; }

    /// <summary>The thread must be STA: the collector uses COM.</summary>
    bool RequiresSta { get; }

    CollectorOutcome Collect(CollectionContext context);
}

/// <summary>Version of the collectors; equals the version of the agent assembly line.</summary>
public static class CollectorVersions
{
    public const string Current = "0.1.0";
}
