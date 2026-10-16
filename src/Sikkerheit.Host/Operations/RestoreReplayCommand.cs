using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Operations;

/// <summary>
/// Maintenance mode of the service image (06 «Резервное копирование и восстановление», RB-05): the same build and
/// configuration as the service, no web server, no jobs and no SQL from the operator.
///   dotnet Sikkerheit.Host.dll restore-replay --since 2026-11-03T14:20:00Z [--drill] [--report /home/LogFiles/restore.json]
/// Exit codes: 0 — done and verified, 1 — failed or not verified, 2 — wrong arguments or jobs still enabled.
/// </summary>
public static partial class RestoreReplayCommand
{
    public const string Name = "restore-replay";

    public const string Usage = """
        Usage: dotnet Sikkerheit.Host.dll restore-replay --since <time> [--drill] [--report <file>]
          --since   restore point of the database, ISO 8601 with offset, e.g. 2026-11-03T14:20:00Z
          --drill   restore drill: report and export files are listed, never moved or deleted
          --report  also write the JSON report to this file
        Runs only with Jobs__Enabled=false (RB-05, step 1).
        """;

    public sealed record Arguments(RestoreOptions Options, string? ReportPath);

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
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger(typeof(RestoreReplayCommand));
        RestoreReport report;
        try
        {
            report = await services.GetRequiredService<RestoreReplay>().RunAsync(arguments.Options, ct);
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

    [GeneratedRegex(@"(Z|[+-]\d{2}:\d{2})$")]
    private static partial Regex ExplicitOffset();
}
