#Requires -Version 5.1
<#
  Tests of Sikkerheit-Rmm.ps1 without Windows: the facts of the machine and the effects (signature, msiexec, ACL, COM) are
  replaced by fakes; the hash, the files and the arguments are real. Output: "PASS <id>" or "FAIL <id>: <why>" per case, then
  "SUMMARY passed=<n> failed=<n>"; exit code 1 on any failure. Negative cases of INV-201 start with "inv201."
  (the contract test tests/Sikkerheit.ContractTests/RmmScriptInvariantTests.cs lists the ones that must exist).
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:Script = Join-Path (Split-Path -Parent $PSScriptRoot) 'Sikkerheit-Rmm.ps1'
$script:Canary = 'sikk_' + ('A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v'.Substring(0, 43))
$script:Publisher = @{ Cn = 'Sikkerheit Test Publisher'; O = 'Sikkerheit Test AS' }
$script:Results = New-Object System.Collections.Generic.List[object]
$script:Root = Join-Path ([IO.Path]::GetTempPath()) ('sikk-rmm-tests-' + [Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $script:Root)

function New-Fake {
    @{
        Os        = [pscustomobject]@{ ProductType = 1; NativeArchitecture = 'AMD64'; Build = 19045 }
        Signature = [pscustomobject]@{ Status = 'Valid'; Subject = 'CN=Sikkerheit Test Publisher, O=Sikkerheit Test AS, C=NO'; Timestamped = $true }
        Version   = '0.3.1'
        Installed = $null
        MsiexecExit = 0
        MsiexecCalls = New-Object System.Collections.Generic.List[object]
        AclCalls  = New-Object System.Collections.Generic.List[string]
        KeyValue  = $null
        FailOnMove = $false
        OsThrows  = $null
    }
}

# One case = a directory with a "MSI" file, a pin, fakes; returns the output, the exit code and the evidence.
function Invoke-Case([hashtable]$Fake, [hashtable]$Arguments, [string]$Action = 'Install', [scriptblock]$Mutate = $null) {
    $dir = Join-Path $script:Root ([Guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $dir)
    $msi = Join-Path $dir 'agent.msi'
    [IO.File]::WriteAllBytes($msi, [Text.Encoding]::UTF8.GetBytes('approved msi payload ' + $dir))
    $sha = (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant()
    $parameters = @{
        Action = $Action; MsiPath = $msi; ApprovedVersion = '0.3.1'; ApprovedSha256 = $sha
        PublisherCommonName = $script:Publisher.Cn; PublisherOrganization = $script:Publisher.O
        DataDirectory = (Join-Path $dir 'data'); StagingDirectory = (Join-Path $dir 'staging')
    }
    foreach ($name in $Arguments.Keys) {
        if ($null -eq $Arguments[$name]) { $parameters.Remove($name) } else { $parameters[$name] = $Arguments[$name] }
    }
    if ($Mutate) { & $Mutate $msi $parameters }
    $state = @{ Dir = $dir; Msi = $msi; Sha = $sha; Fake = $Fake }
    $state.Output = & {
        $fake = $Fake
        . $script:Script @parameters
        function Get-OsFacts { if ($fake.OsThrows) { throw $fake.OsThrows }; $fake.Os }
        function Get-SignatureFacts([string]$Path) { $fake.Signature }
        function Get-MsiProductVersion([string]$Path) { $fake.Version }
        function Get-InstalledAgent { $fake.Installed }
        function Invoke-Msiexec([string[]]$Arguments) { $fake.MsiexecCalls.Add($Arguments); [int]$fake.MsiexecExit }
        function Save-FromUrl([string]$Url, [string]$Destination) { throw "download of $Url" }
        function Protect-Path([string]$Path) { $fake.AclCalls.Add($Path) }
        function Get-KeyFromEnvironment([string]$Variable) { $fake.KeyValue }
        function Clear-KeyFromEnvironment([string]$Variable) { $fake.KeyValue = $null }
        Invoke-Rmm *>&1 | ForEach-Object { "$_" }
    }
    $state.ExitCode = $script:ExitCode
    $state.Text = ($state.Output -join "`n")
    $state.Staged = @(Get-ChildItem -LiteralPath (Join-Path $dir 'staging') -ErrorAction SilentlyContinue)
    $state.KeyFile = Join-Path (Join-Path $dir 'data') 'enrollment.key'
    return $state
}

function Assert-That([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }

function Test-Case([string]$Id, [scriptblock]$Body) {
    try { & $Body; $script:Results.Add(@{ Id = $Id; Ok = $true; Why = '' }); Write-Host "PASS $Id" }
    catch { $script:Results.Add(@{ Id = $Id; Ok = $false; Why = $_.Exception.Message }); Write-Host "FAIL ${Id}: $($_.Exception.Message)" }
}

# Refusal without effect: the code, no msiexec, no key file, nothing left in the staging directory.
function Assert-Refused($Run, [int]$Code, [string]$Reason) {
    Assert-That ($Run.ExitCode -eq $Code) "exit code $($Run.ExitCode), expected $Code; output: $($Run.Text)"
    Assert-That ($Run.Text -match "result=(refused|failed) code=$Code reason=$Reason") "output: $($Run.Text)"
    Assert-That ($Run.Fake.MsiexecCalls.Count -eq 0) 'msiexec was started'
    Assert-That (-not (Test-Path -LiteralPath $Run.KeyFile)) 'a key file was written'
    Assert-That ($Run.Staged.Count -eq 0) 'the staged MSI was left behind'
    Assert-That (-not $Run.Text.Contains($script:Canary)) 'the key is in the output'
}

# ---- negatives of INV-201 ----------------------------------------------------------------------------------------------

Test-Case 'inv201.tampered_msi' {
    $f = New-Fake
    $run = Invoke-Case $f @{} 'Install' { param($msi, $p) [IO.File]::AppendAllText($msi, ' tampered') }
    Assert-Refused $run 31 'sha256_mismatch'
}
Test-Case 'inv201.old_signed_version_not_pinned' {
    # the old vulnerable build is signed by the same publisher and has its own valid version; the job pins another SHA-256
    $f = New-Fake; $f.Version = '0.2.0'
    $run = Invoke-Case $f @{ ApprovedSha256 = ('0' * 64) }
    Assert-Refused $run 31 'sha256_mismatch'
}
Test-Case 'inv201.signed_but_version_not_approved' {
    # right hash (the pin was made for this file) but the MSI says another ProductVersion
    $f = New-Fake; $f.Version = '0.2.0'
    $run = Invoke-Case $f @{}
    Assert-Refused $run 34 'version_mismatch'
}
Test-Case 'inv201.foreign_publisher' {
    $f = New-Fake; $f.Signature.Subject = 'CN=Evil Corp, O=Evil Corp, C=US'
    Assert-Refused (Invoke-Case $f @{}) 33 'publisher_mismatch'
}
Test-Case 'inv201.publisher_with_second_common_name' {
    $f = New-Fake; $f.Signature.Subject = 'CN=Evil Corp, CN=Sikkerheit Test Publisher, O=Sikkerheit Test AS'
    Assert-Refused (Invoke-Case $f @{}) 33 'publisher_mismatch'
}
Test-Case 'inv201.publisher_prefix_or_case' {
    foreach ($subject in @('CN=Sikkerheit Test Publisher X, O=Sikkerheit Test AS', 'CN=sikkerheit test publisher, O=Sikkerheit Test AS',
            'CN=Sikkerheit Test Publisher', 'O=Sikkerheit Test AS', '', $null)) {
        $f = New-Fake; $f.Signature.Subject = $subject
        Assert-Refused (Invoke-Case $f @{}) 33 'publisher_mismatch'
    }
}
Test-Case 'inv201.signature_not_valid' {
    foreach ($status in @('NotSigned', 'HashMismatch', 'NotTrusted', 'UnknownError', 'NotSupportedFileFormat')) {
        $f = New-Fake; $f.Signature.Status = $status
        Assert-Refused (Invoke-Case $f @{}) 32 'signature_invalid'
    }
}
Test-Case 'inv201.signature_without_timestamp' {
    $f = New-Fake; $f.Signature.Timestamped = $false
    Assert-Refused (Invoke-Case $f @{}) 32 'signature_invalid'
}
Test-Case 'inv201.arm64' {
    $f = New-Fake; $f.Os.NativeArchitecture = 'ARM64'
    $run = Invoke-Case $f @{}
    Assert-Refused $run 21 'arch_not_x64'
}
Test-Case 'inv201.server_os' {
    foreach ($type in @(2, 3)) {
        $f = New-Fake; $f.Os.ProductType = $type
        Assert-Refused (Invoke-Case $f @{}) 20 'os_not_client'
    }
}
Test-Case 'inv201.build_below_17763' {
    $f = New-Fake; $f.Os.Build = 17134
    Assert-Refused (Invoke-Case $f @{}) 22 'build_too_old'
}
Test-Case 'inv201.machine_refusal_precedes_any_file_work' {
    # on ARM64 or a server the MSI is not even copied
    $f = New-Fake; $f.Os.NativeArchitecture = 'ARM64'
    $run = Invoke-Case $f @{ MsiPath = (Join-Path $script:Root 'does-not-exist.msi') }
    Assert-Refused $run 21 'arch_not_x64'
}
Test-Case 'inv201.refused_msi_never_writes_the_key' {
    $f = New-Fake; $f.KeyValue = $script:Canary; $f.Signature.Subject = 'CN=Evil Corp, O=Evil Corp'
    $run = Invoke-Case $f @{}
    Assert-Refused $run 33 'publisher_mismatch'
    Assert-That ($f.AclCalls.Count -le 1) 'the data directory was prepared for a refused MSI'
}
Test-Case 'inv201.pin_required' {
    $f = New-Fake
    Assert-Refused (Invoke-Case $f @{ ApprovedSha256 = 'abc' }) 10 'approved_sha256_invalid'
    Assert-Refused (Invoke-Case $f @{ ApprovedVersion = '0.3' }) 10 'approved_version_invalid'
    Assert-Refused (Invoke-Case $f @{ PublisherOrganization = '' }) 10 'publisher_missing'
    Assert-Refused (Invoke-Case $f @{ MsiPath = $null }) 10 'msi_source_ambiguous'
    Assert-Refused (Invoke-Case $f @{ MsiUrl = 'https://x.example/a.msi' }) 10 'msi_source_ambiguous'
}

# ---- other refusals and the happy path ---------------------------------------------------------------------------------

Test-Case 'refuses.missing_msi_and_insecure_url' {
    $f = New-Fake
    Assert-Refused (Invoke-Case $f @{ MsiPath = (Join-Path $script:Root 'none.msi') }) 30 'msi_missing'
    Assert-Refused (Invoke-Case $f @{ MsiPath = $null; MsiUrl = 'http://x.example/a.msi' }) 10 'msi_url_not_https'
}
Test-Case 'download_failure_prints_no_url' {
    $f = New-Fake
    $run = Invoke-Case $f @{ MsiPath = $null; MsiUrl = 'https://store.example/a.msi?sig=SECRETSAS' }
    Assert-That ($run.ExitCode -eq 35) "exit code $($run.ExitCode)"
    Assert-That (-not $run.Text.Contains('SECRETSAS')) 'the SAS token is in the output'
}
Test-Case 'refuses.proxy_with_credentials_or_junk' {
    foreach ($proxy in @('http://user:pass@proxy.example:8080', 'ftp://proxy.example', 'proxy.example:8080', 'http://p.example" /x', 'http://p.example&calc')) {
        $f = New-Fake
        Assert-Refused (Invoke-Case $f @{ Proxy = $proxy }) 11 'proxy_invalid'
    }
}
Test-Case 'install.happy_path' {
    $f = New-Fake
    $run = Invoke-Case $f @{ Proxy = 'http://proxy.example:3128' }
    Assert-That ($run.ExitCode -eq 0) "exit code $($run.ExitCode): $($run.Text)"
    Assert-That ($f.MsiexecCalls.Count -eq 1) 'msiexec was not started once'
    $args = $f.MsiexecCalls[0]
    Assert-That ($args[0] -eq '/i' -and $args -contains '/qn' -and $args -contains '/norestart' -and $args -contains 'REBOOT=ReallySuppress') "arguments: $args"
    Assert-That ($args -contains 'PROXY="http://proxy.example:3128"') "arguments: $args"
    Assert-That ($args[1] -like '*staging*') 'the installed file is not the staged copy'
    Assert-That ($run.Staged.Count -eq 0) 'the staged copy was not removed'
    Assert-That ($run.Text -match 'result=ok code=0 reason=installed') $run.Text
}
Test-Case 'install.already_current_version_does_nothing' {
    $f = New-Fake; $f.Installed = [pscustomobject]@{ ProductCode = '{AAAA}'; Version = '0.3.1' }
    $run = Invoke-Case $f @{}
    Assert-That ($run.ExitCode -eq 0 -and $f.MsiexecCalls.Count -eq 0) $run.Text
    Assert-That ($run.Text -match 'reason=already_installed') $run.Text
}
Test-Case 'install.rollback_to_an_approved_older_version_is_installed' {
    $f = New-Fake; $f.Installed = [pscustomobject]@{ ProductCode = '{AAAA}'; Version = '0.4.0' }
    $run = Invoke-Case $f @{}
    Assert-That ($run.ExitCode -eq 0 -and $f.MsiexecCalls.Count -eq 1) $run.Text
}
Test-Case 'install.failure_code_and_no_key' {
    $f = New-Fake; $f.MsiexecExit = 1603; $f.KeyValue = $script:Canary
    $run = Invoke-Case $f @{}
    Assert-That ($run.ExitCode -eq 40) "exit code $($run.ExitCode)"
    Assert-That ($run.Text -match 'reason=install_failed msiexec=1603') $run.Text
    Assert-That (-not (Test-Path -LiteralPath $run.KeyFile)) 'a key was written after a failed install'
    Assert-That ($run.Staged.Count -eq 0) 'the staged copy was left behind'
}
Test-Case 'install.reboot_pending_is_success' {
    $f = New-Fake; $f.MsiexecExit = 3010
    Assert-That ((Invoke-Case $f @{}).ExitCode -eq 0) 'exit 3010 is not a failure'
}
Test-Case 'install.writes_the_key_after_the_install' {
    $f = New-Fake; $f.KeyValue = $script:Canary
    $run = Invoke-Case $f @{}
    Assert-That ($run.ExitCode -eq 0) $run.Text
    Assert-That ((Get-Content -LiteralPath $run.KeyFile -Raw) -ceq $script:Canary) 'the key file differs'
    Assert-That (($f.MsiexecCalls | ForEach-Object { $_ -join ' ' }) -notmatch 'sikk_') 'the key is on the command line'
    Assert-That (-not $run.Text.Contains($script:Canary)) 'the key is in the output'
}

# ---- the key file (04, INV-201 side: no key on the command line and in the logs 4688 / 4104) ---------------------------

Test-Case 'key.file_content_acl_and_no_trace' {
    $f = New-Fake; $f.Installed = [pscustomobject]@{ ProductCode = '{AAAA}'; Version = '0.3.1' }; $f.KeyValue = "  $($script:Canary)`r`n"
    $oldVerbose = $VerbosePreference; $oldDebug = $DebugPreference
    $VerbosePreference = 'Continue'; $DebugPreference = 'Continue'
    try { $run = Invoke-Case $f @{} 'SetEnrollmentKey' } finally { $VerbosePreference = $oldVerbose; $DebugPreference = $oldDebug }
    Assert-That ($run.ExitCode -eq 0) "exit code $($run.ExitCode): $($run.Text)"
    Assert-That ((Get-Content -LiteralPath $run.KeyFile -Raw) -ceq $script:Canary) 'the key file has other content (a trim, no newline, no BOM expected)'
    $bytes = [IO.File]::ReadAllBytes($run.KeyFile)
    Assert-That ($bytes.Length -eq 48 -and $bytes[0] -eq [byte][char]'s') 'BOM or newline in the key file'
    Assert-That (-not (Test-Path -LiteralPath ($run.KeyFile + '.tmp'))) 'the temporary file was left'
    Assert-That ($f.AclCalls.Count -ge 2) 'the data directory and the file must both be restricted'
    Assert-That ($f.AclCalls[$f.AclCalls.Count - 1] -like '*enrollment.key.tmp') 'the file must be restricted before the key is moved to its name'
    Assert-That ($null -eq $f.KeyValue) 'the key stayed in the environment of the process'
    Assert-That (-not $run.Text.Contains($script:Canary)) 'the key is in the output (all streams, verbose and debug on)'
    Assert-That ($run.Text -notmatch 'sikk_') 'a key prefix is in the output'
    Assert-That ($f.MsiexecCalls.Count -eq 0) 'msiexec was started to write a key'
}
Test-Case 'key.invalid_formats_are_refused_without_echo' {
    foreach ($bad in @('sikk_short', 'sikk_' + ('A' * 44), 'xxxx_' + ('A' * 43), ('sikk_' + ('A' * 20) + ' ' + ('B' * 22)), ('sikk_' + ('A' * 42) + ';'), "sikk_$('A' * 43)`nmore")) {
        $f = New-Fake; $f.Installed = [pscustomobject]@{ ProductCode = '{AAAA}'; Version = '0.3.1' }; $f.KeyValue = $bad
        $run = Invoke-Case $f @{} 'SetEnrollmentKey'
        Assert-That ($run.ExitCode -eq 51) "exit code $($run.ExitCode) for a malformed key"
        Assert-That (-not (Test-Path -LiteralPath $run.KeyFile)) 'a malformed key was written'
        Assert-That (-not $run.Text.Contains($bad.Trim())) 'the malformed key was echoed'
    }
}
Test-Case 'key.empty_variable_and_agent_not_installed' {
    $f = New-Fake; $f.Installed = [pscustomobject]@{ ProductCode = '{AAAA}'; Version = '0.3.1' }
    Assert-That ((Invoke-Case $f @{} 'SetEnrollmentKey').ExitCode -eq 50) 'empty variable'
    $f = New-Fake; $f.KeyValue = $script:Canary
    $run = Invoke-Case $f @{} 'SetEnrollmentKey'
    Assert-That ($run.ExitCode -eq 53 -and -not (Test-Path -LiteralPath $run.KeyFile)) "a key was written without an agent: $($run.Text)"
}
Test-Case 'key.write_failure_leaves_no_file_and_no_text' {
    $f = New-Fake; $f.Installed = [pscustomobject]@{ ProductCode = '{AAAA}'; Version = '0.3.1' }; $f.KeyValue = $script:Canary
    $run = Invoke-Case $f @{ DataDirectory = (Join-Path $script:Root 'file-instead-of-directory') } 'SetEnrollmentKey' {
        param($msi, $p) [IO.File]::WriteAllText($p.DataDirectory, 'x') }
    Assert-That ($run.ExitCode -eq 52) "exit code $($run.ExitCode): $($run.Text)"
    Assert-That (-not $run.Text.Contains($script:Canary)) 'the key is in the output'
    Assert-That ($null -eq $f.KeyValue) 'the key stayed in the environment after a failure'
}
Test-Case 'unexpected_error_prints_only_the_type' {
    $f = New-Fake; $f.OsThrows = "boom with $($script:Canary) and C:\secret\path"
    $run = Invoke-Case $f @{}
    Assert-That ($run.ExitCode -eq 60) "exit code $($run.ExitCode)"
    Assert-That ($run.Text -match 'reason=unexpected type=') $run.Text
    Assert-That (-not $run.Text.Contains($script:Canary) -and -not $run.Text.Contains('secret')) 'the message of the exception was printed'
}
Test-Case 'uninstall.removes_by_product_code' {
    $f = New-Fake; $f.Installed = [pscustomobject]@{ ProductCode = '{11111111-2222-3333-4444-555555555555}'; Version = '0.3.1' }
    $run = Invoke-Case $f @{} 'Uninstall'
    Assert-That ($run.ExitCode -eq 0 -and $f.MsiexecCalls[0][0] -eq '/x') $run.Text
    $f = New-Fake
    $run = Invoke-Case $f @{} 'Uninstall'
    Assert-That ($run.ExitCode -eq 0 -and $f.MsiexecCalls.Count -eq 0 -and $run.Text -match 'not_installed') $run.Text
}

# ---- the script text: nothing that could print or log a key ------------------------------------------------------------

Test-Case 'static.no_key_parameter_and_no_printing_commands' {
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Script, [ref]$tokens, [ref]$errors)
    Assert-That ($errors.Count -eq 0) 'syntax errors'
    $names = $ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }
    $keyLike = @($names | Where-Object { $_ -match '(?i)key|secret|token|password' -and $_ -ne 'KeyVariable' })
    Assert-That ($keyLike.Count -eq 0) "a parameter could carry a secret: $keyLike"
    $commands = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
        ForEach-Object { $_.GetCommandName() } | Where-Object { $_ }
    $banned = @('Write-Host', 'Write-Verbose', 'Write-Debug', 'Write-Warning', 'Write-Error', 'Write-Information', 'Start-Transcript',
        'Invoke-Expression', 'Out-File', 'Add-Content', 'Set-Content', 'Tee-Object', 'Export-Clixml')
    $found = @($commands | Where-Object { $banned -contains $_ })
    Assert-That ($found.Count -eq 0) "commands that print or write: $found"
    $text = Get-Content -LiteralPath $script:Script -Raw
    Assert-That (([regex]::Matches($text, 'sikk_')).Count -eq 1) 'a literal key prefix other than the format check'
    Assert-That ($text -notmatch '-Verbose|-Debug\b|Set-PSDebug|\$VerbosePreference') 'verbose or debug switches in the script'
}
Test-Case 'static.distinguished_name_parser' {
    . $script:Script -Action Uninstall
    $pairs = ConvertFrom-DistinguishedName 'CN="Doe, Inc.", O=Org\, AS, C=NO'
    Assert-That ($pairs.Count -eq 3 -and $pairs[0].Value -eq 'Doe, Inc.' -and $pairs[1].Value -eq 'Org, AS') 'quoted and escaped commas'
}

Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue
$failed = @($script:Results | Where-Object { -not $_.Ok }).Count
Write-Host "SUMMARY passed=$($script:Results.Count - $failed) failed=$failed"
exit ([int]($failed -gt 0))
