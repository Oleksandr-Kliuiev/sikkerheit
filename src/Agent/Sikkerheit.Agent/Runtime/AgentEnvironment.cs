using System.Diagnostics;
using Sikkerheit.Agent.Storage;

namespace Sikkerheit.Agent.Runtime;

/// <summary>Files of the data directory (02): the database, the identifier of the installation and the registration key.</summary>
public sealed class AgentPaths(string dataDirectory)
{
    public string DataDirectory { get; } = dataDirectory;

    public string Database => Path.Combine(DataDirectory, "agent.db");

    public string InstallationIdFile => Path.Combine(DataDirectory, "installation.id");

    /// <summary>The key file from RMM: read, saved under DPAPI and deleted.</summary>
    public string IncomingKeyFile => Path.Combine(DataDirectory, "enrollment.key");

    public string ProtectedKeyFile => Path.Combine(DataDirectory, "enrollment.key.dpapi");
}

/// <summary>Probe of the process and the machine for the telemetry and the schedule.</summary>
public interface ISystemProbe
{
    string MachineName { get; }

    long WorkingSetMb { get; }

    long CpuSeconds { get; }

    /// <summary>The time of the start of the OS: a planned collection starts 60 minutes after it (03, WIN-004).</summary>
    DateTimeOffset BootTime { get; }
}

public sealed class ProcessProbe(TimeProvider time) : ISystemProbe
{
    public string MachineName => Environment.MachineName;

    public long WorkingSetMb => Environment.WorkingSet / (1024 * 1024);

    public long CpuSeconds
    {
        get
        {
            using var process = Process.GetCurrentProcess();
            return (long)process.TotalProcessorTime.TotalSeconds;
        }
    }

    public DateTimeOffset BootTime => time.GetUtcNow() - TimeSpan.FromMilliseconds(Environment.TickCount64);
}

/// <summary>Settings of the service: the hostname of the agent and the data directory (the MSI writes them; the key is not among them).</summary>
public sealed class AgentOptions
{
    public const string Section = "Agent";

    public string ServerUrl { get; set; } = "";

    public string DataDirectory { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sikkerheit", "Agent");

    /// <summary>Proxy of the MSI property PROXY; otherwise the system proxy of WinHTTP or a direct connection (02).</summary>
    public string? Proxy { get; set; }

    public void Validate()
    {
        if (!Uri.TryCreate(ServerUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new InvalidOperationException("Agent:ServerUrl must be an https URL of the agent hostname");
        }
        if (Proxy is not null && !Uri.TryCreate(Proxy, UriKind.Absolute, out _))
        {
            throw new InvalidOperationException("Agent:Proxy must be an absolute URL");
        }
    }
}

public static class AgentLimits
{
    /// <summary>The pause before the first planned collection after the start of the OS.</summary>
    public static readonly TimeSpan BootDelay = TimeSpan.FromMinutes(60);

    public static readonly TimeSpan DailyAttempt = TimeSpan.FromHours(24);

    public static readonly TimeSpan VersionBlockedCheckIn = TimeSpan.FromHours(4);

    public static readonly TimeSpan KeyFilePoll = TimeSpan.FromMinutes(1);

    public static readonly TimeSpan SessionMargin = TimeSpan.FromMinutes(2);

    public static readonly TimeSpan EnrollmentRetention = TimeSpan.FromHours(24);

    public static readonly TimeSpan BackoffMin = TimeSpan.FromMinutes(1);

    public static readonly TimeSpan BackoffMax = TimeSpan.FromHours(1);

    /// <summary>A batch is unfit after five answers 500 with a successful check-in between the attempts.</summary>
    public const int ServerErrorLimit = 5;

    /// <summary>Check-in interval before the first configuration arrives.</summary>
    public static readonly TimeSpan DefaultCheckIn = TimeSpan.FromHours(4);
}
