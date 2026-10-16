using System.Diagnostics;
using Sikkerheit.ContractTests.Invariants;

namespace Sikkerheit.ContractTests;

/// <summary>
/// INV-201 (WP-11): the script of the RMM installs only the approved MSI. The negative cases run in PowerShell (pwsh) against the
/// real script with the facts of the machine and the effects replaced (tools/rmm/tests/Run-RmmTests.ps1): a changed MSI, an MSI of
/// another publisher, a correctly signed but not approved version, ARM64 and a server OS must end in a refusal with no msiexec, no
/// key file and no key in the output. The runner must report every case named here as passed, so a deleted case fails the build.
/// What only Windows confirms (real signature, COM, ACL, msiexec) is in docs/dev/rmm-windows-verification.md (SP-05).
/// </summary>
[Enforcement("infra")]
public sealed class RmmScriptInvariantTests
{
    private static readonly string[] Required =
    [
        "inv201.tampered_msi", "inv201.old_signed_version_not_pinned", "inv201.signed_but_version_not_approved", "inv201.foreign_publisher",
        "inv201.publisher_with_second_common_name", "inv201.publisher_prefix_or_case", "inv201.signature_not_valid",
        "inv201.signature_without_timestamp", "inv201.arm64", "inv201.server_os", "inv201.build_below_17763",
        "inv201.machine_refusal_precedes_any_file_work", "inv201.refused_msi_never_writes_the_key", "inv201.pin_required",
        "install.happy_path", "key.file_content_acl_and_no_trace", "key.invalid_formats_are_refused_without_echo",
        "unexpected_error_prints_only_the_type", "static.no_key_parameter_and_no_printing_commands",
    ];

    private static string? FindPwsh()
    {
        foreach (var directory in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
        {
            var candidate = Path.Combine(directory, OperatingSystem.IsWindows() ? "pwsh.exe" : "pwsh");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        return null;
    }

    [Fact]
    [Invariant("INV-201")]
    public async Task Script_of_the_RMM_refuses_everything_but_the_approved_MSI()
    {
        var pwsh = FindPwsh();
        if (pwsh is null)
        {
            Assert.True(Environment.GetEnvironmentVariable("CI") is null, "pwsh is required on CI to test the RMM script (INV-201)");
            Assert.Skip("pwsh is not installed: the RMM script (INV-201) is tested with PowerShell 7 (brew install powershell)");
        }
        var runner = Path.Combine(InvariantRegistry.Root, "tools", "rmm", "tests", "Run-RmmTests.ps1");
        var start = new ProcessStartInfo(pwsh, ["-NoProfile", "-NonInteractive", "-File", runner])
        {
            RedirectStandardOutput = true, RedirectStandardError = true,
        };
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        var error = process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(3));
        await process.WaitForExitAsync(timeout.Token);
        var lines = (await output).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var report = string.Join('\n', lines.Where(l => l.StartsWith("FAIL", StringComparison.Ordinal) || l.StartsWith("SUMMARY", StringComparison.Ordinal))) + await error;

        Assert.True(process.ExitCode == 0, "The RMM script tests failed:\n" + report);
        var passed = lines.Where(l => l.StartsWith("PASS ", StringComparison.Ordinal)).Select(l => l[5..]).ToHashSet();
        var missing = Required.Where(id => !passed.Contains(id)).ToList();
        Assert.True(missing.Count == 0, "Cases of INV-201 that did not run: " + string.Join(", ", missing));
    }
}
