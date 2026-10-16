#Requires -Version 5.1
# Parses every PowerShell file of the repository tools and the installer (PSScriptAnalyzer is not installed on the machines of the project).
# Exit code 1 and "file:line: message" on a syntax error.
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$files = Get-ChildItem -Path (Join-Path $root 'tools\rmm'), (Join-Path $root 'src\Agent\Installer') -Recurse -Include *.ps1 -File
$failed = 0
foreach ($file in $files) {
    $tokens = $null; $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    foreach ($e in $errors) { $failed++; Write-Output "$($file.FullName):$($e.Extent.StartLineNumber): $($e.Message)" }
}
Write-Output "syntax: $($files.Count) files, $failed errors"
exit ([int]($failed -gt 0))
