using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using Azure.Identity;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Operations;

/// <summary>
/// Maintenance mode of the service image (06 «Резервное копирование и восстановление», RB-05): the same build and
/// configuration as the service, no web server, no jobs and no SQL from the operator.
///   dotnet Sikkerheit.Host.dll restore-replay --since 2026-11-03T14:20:00Z [--drill] [--report /home/LogFiles/restore.json]
/// Exit codes: 0 — done and verified, 1 — failed or not verified, 2 — wrong arguments, jobs still enabled or no restore
/// identity.
/// </summary>
public static partial class RestoreReplayCommand
{
    public const string Name = "restore-replay";

    /// <summary>Client id of the restore identity id-sikkerheit-&lt;env&gt;-restore (main.bicep), as Restore__ManagedIdentityClientId.</summary>
    public const string IdentitySetting = "Restore:ManagedIdentityClientId";

    public const string Usage = """
        Usage: dotnet Sikkerheit.Host.dll restore-replay --since <time> [--drill] [--report <file>]
          --since   restore point of the database, ISO 8601 with offset, e.g. 2026-11-03T14:20:00Z
          --drill   restore drill: report and export files are listed, never moved or deleted
          --report  also write the JSON report to this file
        Runs only with Jobs__Enabled=false (RB-05, step 1). In Azure the security log is read with the restore
        identity Restore__ManagedIdentityClientId; a real restore moves files with the identity of the slot.
        """;

    public sealed record Arguments(RestoreOptions Options, string? ReportPath);

    public sealed record Stores(ISecurityLog SecurityLog, IFileStore Files);

    public static bool Matches(string[] args) => args.Length > 0 && args[0] == Name;

    /// <summary>Parses the arguments after the command name; null with an error message when they are wrong.</summary>
    public static Arguments? Parse(IReadOnlyList<string> args, DateTimeOffset now, out string? error)
    {
        DateTimeOffset? since = null;
        string? report = null;
        var drill = false;
        for (var i = 0; i < args.Count; i++)
        {
            switch (args[i])
            {
                case "--since" when i + 1 < args.Count && since is null:
                    var value = args[++i];
                    if (!ExplicitOffset().IsMatch(value) || !DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture,
                            DateTimeStyles.None, out var parsed))
                    {
                        error = "--since must be an ISO 8601 time with an offset, for example 2026-11-03T14:20:00Z";
                        return null;
                    }
                    since = parsed.ToUniversalTime();
                    break;
                case "--report" when i + 1 < args.Count && report is null:
                    report = args[++i];
                    break;
                case "--drill" when !drill:
                    drill = true;
                    break;
                default:
                    error = $"unexpected argument '{args[i]}'";
                    return null;
            }
        }
        if (since is null)
        {
            error = "--since is required";
            return null;
        }
        if (since > now)
        {
            error = "--since lies in the future";
            return null;
        }
        error = null;
        return new Arguments(new RestoreOptions(since.Value, drill), report);
    }

    public static async Task<int> RunAsync(IServiceProvider services, IReadOnlyList<string> args, TextWriter output,
        TextWriter errors, CancellationToken ct)
    {
        var configuration = services.GetRequiredService<IConfiguration>();
        var arguments = Parse(args, services.GetRequiredService<TimeProvider>().GetUtcNow(), out var error);
        if (arguments is null)
        {
            await errors.WriteLineAsync(error + Environment.NewLine + Usage);
            return 2;
        }
        // The replay resets leases and changes organizations: a running job runner would race with it.
        if (configuration.GetValue("Jobs:Enabled", false))
        {
            await errors.WriteLineAsync("Jobs are enabled here: set Jobs__Enabled=false first (RB-05, step 1).");
            return 2;
        }
        var stores = StoresOf(services, configuration, arguments.Options.Drill, out var refusal);
        if (stores is null)
        {
            await errors.WriteLineAsync(refusal);
            return 2;
        }
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger(typeof(RestoreReplayCommand));
        if (configuration[IdentitySetting] is { Length: > 0 } restoreIdentity)
        {
            logger.LogInformation("Security log read with the restore identity {ClientId}; files with the {FilesIdentity} identity",
                restoreIdentity, arguments.Options.Drill ? "restore" : "slot");
        }
        var replay = new RestoreReplay(services.GetRequiredService<DbScopes>(), stores.SecurityLog, stores.Files,
            services.GetRequiredService<TimeProvider>(), services.GetRequiredService<ILogger<RestoreReplay>>());
        RestoreReport report;
        try
        {
            report = await replay.RunAsync(arguments.Options, ct);
        }
        catch (Exception failure) when (failure is not OperationCanceledException)
        {
            logger.LogError(failure, "Restore replay failed");
            await errors.WriteLineAsync("Restore replay failed: " + failure.Message);
            return 1;
        }
        var json = JsonSerializer.Serialize(report, new JsonSerializerOptions(ApiJson.Options) { WriteIndented = true });
        await output.WriteLineAsync(json);
        if (arguments.ReportPath is { } path)
        {
            await File.WriteAllTextAsync(path, json, ct);
        }
        return report.Verification.Passed ? 0 : 1;
    }

    /// <summary>
    /// The security log and the files of one run. The identity of the restore command may only read the security log
    /// (04 «Журнал безопасности»), so in Azure the log is read with the restore identity: Storage Blob Data Reader on
    /// security-log, reports and exports. A drill lists the files with it too and cannot move them. A real restore moves
    /// files without rows to quarantine and deletes the files of deleted organizations, so its files stay with the
    /// identity of the slot. Only the managed identity itself, never another credential of a chain, may stand for the
    /// restore identity. Development and tests keep the local stores. Null with the reason when Azure is configured
    /// without the restore identity.
    /// </summary>
    public static Stores? StoresOf(IServiceProvider services, IConfiguration configuration, bool drill, out string? refusal)
    {
        refusal = null;
        var container = configuration["SecurityLog:ContainerUri"];
        if (string.IsNullOrEmpty(container))
        {
            return new Stores(services.GetRequiredService<ISecurityLog>(), services.GetRequiredService<IFileStore>());
        }
        var clientId = configuration[IdentitySetting];
        if (string.IsNullOrEmpty(clientId))
        {
            refusal = "Restore__ManagedIdentityClientId is not set: the restore command reads the security log only with "
                + "the restore identity id-sikkerheit-<env>-restore (RB-05, step 3).";
            return null;
        }
        var credential = new ManagedIdentityCredential(ManagedIdentityId.FromUserAssignedClientId(clientId));
        var account = configuration["Storage:BlobServiceUri"];
        var files = drill && !string.IsNullOrEmpty(account)
            ? new BlobFileStore(new Uri(account), credential)
            : services.GetRequiredService<IFileStore>();
        return new Stores(new BlobSecurityLog(new Uri(container), credential), files);
    }

    [GeneratedRegex(@"(Z|[+-]\d{2}:\d{2})$")]
    private static partial Regex ExplicitOffset();
}
