#Requires -Version 5.1
<#
.SYNOPSIS
  Script of the RMM for the Sikkerheit agent (WP-11; 06 «Распространение агента через RMM», 04 «Ключ регистрации организации»).

.DESCRIPTION
  Runs as SYSTEM on a client PC. Actions:
    Install            installs the approved MSI (version and SHA-256 are pinned by the job), then writes the key file
                       when the secret variable of the RMM is set;
    SetEnrollmentKey   writes enrollment.key only (rotation of the key, RB-10); no reinstall;
    Uninstall          removes the agent through its product code.

  The MSI is installed only if ALL of these hold: a client OS (not a server), native x64 (not ARM64 under emulation), a build
  of Windows 10 1809 or newer; the SHA-256 of the file equals the pinned one; the Authenticode status is Valid with a timestamp;
  the subject of the signer has exactly the pinned CN and O; ProductVersion of the MSI equals the pinned version (INV-201).
  The file is copied to a directory that only SYSTEM can write before any check, so the file that was checked is the file that
  is installed.

  The registration key is NEVER a parameter, an argument of a process or an output: it comes from the process environment
  variable named by -KeyVariable (the secret variable of the RMM, not text substituted into the script - substituted text
  would be logged by PowerShell as event 4104), is written to a file that only SYSTEM can read and is not echoed anywhere.
  Every line of the output is "SIKKERHEIT-RMM result=<ok|refused|failed> code=<n> reason=<word>" plus numbers and versions.

  Exit codes: 0 ok; 10 invalid arguments; 11 invalid proxy; 20 not a client OS; 21 not native x64; 22 build too old;
  30 MSI missing; 31 SHA-256 differs; 32 signature not valid or without timestamp; 33 publisher differs; 34 version differs;
  35 download failed; 40 install failed; 41 uninstall failed; 50 key variable empty; 51 key format invalid; 52 key write failed;
  53 agent not installed; 60 unexpected error.

.EXAMPLE
  # The RMM sets SIKKERHEIT_ENROLLMENT_KEY as a secret environment variable of the job.
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File Sikkerheit-Rmm.ps1 -Action Install -MsiPath .\Sikkerheit.Agent.msi `
    -ApprovedVersion 0.3.1 -ApprovedSha256 <sha256> -PublisherCommonName "<CN>" -PublisherOrganization "<O>"
#>
[CmdletBinding()]
param(
    [ValidateSet('Install', 'SetEnrollmentKey', 'Uninstall')]
    [string]$Action = 'Install',
    [string]$MsiPath,
    [string]$MsiUrl,
    [string]$ApprovedVersion,
    [string]$ApprovedSha256,
    [string]$PublisherCommonName,
    [string]$PublisherOrganization,
    [string]$Proxy,
    [string]$KeyVariable = 'SIKKERHEIT_ENROLLMENT_KEY',
    [string]$DataDirectory,
    [string]$StagingDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:ServiceName = 'Sikkerheit.Agent'
$script:ProductName = 'Sikkerheit Agent'
$script:MinimumBuild = 17763

# Reasons are fixed words: a message of an exception can carry a path, a URL with a SAS token or a value, so it is never printed.
# The refusal is an ordinary exception with its code and reason in Data (no class: the file is dot-sourced by the tests).
function Stop-Rmm([int]$Code, [string]$Reason) {
    $exception = New-Object System.InvalidOperationException('rmm refusal')
    $exception.Data['RmmCode'] = $Code
    $exception.Data['RmmReason'] = $Reason
    throw $exception
}

function Write-Result([string]$Result, [int]$Code, [string]$Reason, [string]$Extra) {
    $line = "SIKKERHEIT-RMM result=$Result code=$Code reason=$Reason"
    if ($Extra) { $line += " $Extra" }
    Write-Output $line
}

# ---- facts of the machine and effects: separate functions so that the tests replace them -------------------------------

function Get-OsFacts {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $arch = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name 'PROCESSOR_ARCHITECTURE').PROCESSOR_ARCHITECTURE
    [pscustomobject]@{ ProductType = [int]$os.ProductType; NativeArchitecture = [string]$arch; Build = [int]$os.BuildNumber }
}

function Get-FileSha256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-SignatureFacts([string]$Path) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    $subject = $null
    if ($null -ne $signature.SignerCertificate) { $subject = $signature.SignerCertificate.Subject }
    [pscustomobject]@{
        Status      = [string]$signature.Status
        Subject     = $subject
        Timestamped = ($null -ne $signature.TimeStamperCertificate)
    }
}

function Get-MsiProductVersion([string]$Path) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    try {
        $database = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($Path, 0))
        $view = $database.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $database,
            @('SELECT `Value` FROM `Property` WHERE `Property` = ''ProductVersion'''))
        $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
        $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
        if ($null -eq $record) { return $null }
        return [string]$record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, @(1))
    }
    finally {
        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($installer)
    }
}

function Get-InstalledAgent {
    $roots = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($key in Get-ChildItem -LiteralPath $root) {
            $entry = Get-ItemProperty -LiteralPath $key.PSPath
            if ($entry.PSObject.Properties['DisplayName'] -and $entry.DisplayName -eq $script:ProductName) {
                return [pscustomobject]@{ ProductCode = $key.PSChildName; Version = [string]$entry.DisplayVersion }
            }
        }
    }
    return $null
}

function Invoke-Msiexec([string[]]$Arguments) {
    $process = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden
    return [int]$process.ExitCode
}

function Save-FromUrl([string]$Url, [string]$Destination) {
    # TLS 1.2 for Windows PowerShell 5.1; the URL (a SAS link) is a secret and is never printed.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing
}

# SYSTEM only, no inheritance (the same rule as the data directory of the agent).
function Protect-Path([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
    $system = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $isDirectory = (Get-Item -LiteralPath $Path).PSIsContainer
    if ($isDirectory) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($system, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    }
    else {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($system, 'FullControl', 'Allow')
    }
    $acl.AddAccessRule($rule)
    $acl.SetOwner($system)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Get-KeyFromEnvironment([string]$Variable) {
    [Environment]::GetEnvironmentVariable($Variable, 'Process')
}

function Clear-KeyFromEnvironment([string]$Variable) {
    [Environment]::SetEnvironmentVariable($Variable, $null, 'Process')
}

# ---- checks ------------------------------------------------------------------------------------------------------------

function Test-Arguments {
    if ($ApprovedVersion -notmatch '^\d{1,5}\.\d{1,5}\.\d{1,5}(\.\d{1,5})?$') { Stop-Rmm 10 'approved_version_invalid' }
    if ($ApprovedSha256 -notmatch '^[0-9A-Fa-f]{64}$') { Stop-Rmm 10 'approved_sha256_invalid' }
    if ([string]::IsNullOrWhiteSpace($PublisherCommonName) -or [string]::IsNullOrWhiteSpace($PublisherOrganization)) { Stop-Rmm 10 'publisher_missing' }
    if ([string]::IsNullOrWhiteSpace($MsiPath) -eq [string]::IsNullOrWhiteSpace($MsiUrl)) { Stop-Rmm 10 'msi_source_ambiguous' }
    if ($MsiUrl -and $MsiUrl -notmatch '^https://') { Stop-Rmm 10 'msi_url_not_https' }
    if ($Proxy) {
        # The command line of msiexec is logged (4688): a proxy with credentials must not be passed.
        $uri = $null
        if (-not [Uri]::TryCreate($Proxy, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -notin @('http', 'https') -or $uri.UserInfo `
                -or $Proxy -match '[\s"&|<>^%]') { Stop-Rmm 11 'proxy_invalid' }
    }
}

function Test-Machine {
    $facts = Get-OsFacts
    if ($facts.ProductType -ne 1) { Stop-Rmm 20 'os_not_client' }
    if ($facts.NativeArchitecture -ne 'AMD64') { Stop-Rmm 21 'arch_not_x64' }
    if ($facts.Build -lt $script:MinimumBuild) { Stop-Rmm 22 'build_too_old' }
}

# "CN=...,O=..." into name/value pairs; commas inside quotes and after a backslash do not split.
function ConvertFrom-DistinguishedName([string]$Dn) {
    $pairs = New-Object System.Collections.Generic.List[object]
    $builder = New-Object System.Text.StringBuilder
    $quoted = $false
    $escaped = $false
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($ch in $Dn.ToCharArray()) {
        if ($escaped) { [void]$builder.Append($ch); $escaped = $false; continue }
        if ($ch -eq '\') { $escaped = $true; continue }
        if ($ch -eq '"') { $quoted = -not $quoted; continue }
        if ($ch -eq ',' -and -not $quoted) { $parts.Add($builder.ToString()); [void]$builder.Clear(); continue }
        [void]$builder.Append($ch)
    }
    $parts.Add($builder.ToString())
    foreach ($part in $parts) {
        $index = $part.IndexOf('=')
        if ($index -gt 0) {
            $pairs.Add([pscustomobject]@{ Name = $part.Substring(0, $index).Trim().ToUpperInvariant(); Value = $part.Substring($index + 1).Trim() })
        }
    }
    return , $pairs.ToArray()
}

function Test-Publisher([string]$Subject) {
    if ([string]::IsNullOrWhiteSpace($Subject)) { return $false }
    $pairs = ConvertFrom-DistinguishedName $Subject
    $names = @($pairs | Where-Object { $_.Name -eq 'CN' })
    $organizations = @($pairs | Where-Object { $_.Name -eq 'O' })
    # exactly one CN and one O: a second CN or O in the subject does not widen the match
    if ($names.Count -ne 1 -or $organizations.Count -ne 1) { return $false }
    return ($names[0].Value -ceq $PublisherCommonName) -and ($organizations[0].Value -ceq $PublisherOrganization)
}

function Get-StagingDirectory {
    $directory = $StagingDirectory
    if (-not $directory) { $directory = Join-Path $env:ProgramData 'Sikkerheit\Staging' }
    if (-not (Test-Path -LiteralPath $directory)) { [void](New-Item -ItemType Directory -Path $directory) }
    Protect-Path $directory
    return $directory
}

# The approved MSI in a directory that only SYSTEM can write: checked and installed is one and the same file.
function Get-StagedMsi {
    $directory = Get-StagingDirectory
    $target = Join-Path $directory ([Guid]::NewGuid().ToString('N') + '.msi')
    if ($MsiPath) {
        if (-not (Test-Path -LiteralPath $MsiPath -PathType Leaf)) { Stop-Rmm 30 'msi_missing' }
        Copy-Item -LiteralPath $MsiPath -Destination $target
    }
    else {
        try { Save-FromUrl $MsiUrl $target } catch { Stop-Rmm 35 'download_failed' }
        if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { Stop-Rmm 35 'download_failed' }
    }
    return $target
}

function Assert-ApprovedMsi([string]$Path) {
    if ((Get-FileSha256 $Path) -ne $ApprovedSha256.ToLowerInvariant()) { Stop-Rmm 31 'sha256_mismatch' }
    $signature = Get-SignatureFacts $Path
    if ($signature.Status -ne 'Valid' -or -not $signature.Timestamped) { Stop-Rmm 32 'signature_invalid' }
    if (-not (Test-Publisher $signature.Subject)) { Stop-Rmm 33 'publisher_mismatch' }
    if ((Get-MsiProductVersion $Path) -ne $ApprovedVersion) { Stop-Rmm 34 'version_mismatch' }
}

# ---- actions -----------------------------------------------------------------------------------------------------------

function Resolve-DataDirectory {
    if ($DataDirectory) { return $DataDirectory }
    return Join-Path $env:ProgramData 'Sikkerheit\Agent'
}

function Write-EnrollmentKeyFile {
    $key = Get-KeyFromEnvironment $KeyVariable
    if ([string]::IsNullOrEmpty($key)) { Stop-Rmm 50 'key_variable_empty' }
    $key = $key.Trim()
    if ($key -notmatch '^sikk_[A-Za-z0-9_-]{43}$') { Stop-Rmm 51 'key_format_invalid' }
    $directory = Resolve-DataDirectory
    $temp = Join-Path $directory 'enrollment.key.tmp'
    try {
        if (-not (Test-Path -LiteralPath $directory)) { [void](New-Item -ItemType Directory -Path $directory) }
        Protect-Path $directory
        # the empty file gets its ACL before the key is written into it; the agent reads enrollment.key only
        [void](New-Item -ItemType File -Path $temp -Force)
        Protect-Path $temp
        [IO.File]::WriteAllBytes($temp, (New-Object System.Text.UTF8Encoding($false)).GetBytes($key))
        Move-Item -LiteralPath $temp -Destination (Join-Path $directory 'enrollment.key') -Force
    }
    catch {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
        Stop-Rmm 52 'key_write_failed'
    }
    finally {
        $key = $null
        Clear-KeyFromEnvironment $KeyVariable
    }
}

function Invoke-Install {
    Test-Arguments
    Test-Machine
    $staged = Get-StagedMsi
    try {
        Assert-ApprovedMsi $staged
        $installed = Get-InstalledAgent
        if ($null -ne $installed -and $installed.Version -eq $ApprovedVersion) {
            $state = 'already_installed'
        }
        else {
            # MajorUpgrade allows a downgrade (rollback to a previously approved version); the data directory is kept.
            $arguments = @('/i', "`"$staged`"", '/qn', '/norestart', 'REBOOT=ReallySuppress')
            if ($Proxy) { $arguments += "PROXY=`"$Proxy`"" }
            $exit = Invoke-Msiexec $arguments
            if ($exit -notin @(0, 1641, 3010)) { Stop-Rmm 40 "install_failed msiexec=$exit" }
            $state = 'installed'
        }
    }
    finally {
        if (Test-Path -LiteralPath $staged) { Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue }
    }
    $keyState = 'key_not_requested'
    if (-not [string]::IsNullOrEmpty((Get-KeyFromEnvironment $KeyVariable))) {
        Write-EnrollmentKeyFile
        $keyState = 'key_file_written'
    }
    Write-Result 'ok' 0 $state "version=$ApprovedVersion $keyState"
}

function Invoke-SetEnrollmentKey {
    Test-Machine
    if ($null -eq (Get-InstalledAgent)) { Stop-Rmm 53 'agent_not_installed' }
    Write-EnrollmentKeyFile
    Write-Result 'ok' 0 'key_file_written' ''
}

function Invoke-Uninstall {
    $installed = Get-InstalledAgent
    if ($null -eq $installed) {
        Write-Result 'ok' 0 'not_installed' ''
        return
    }
    $exit = Invoke-Msiexec @('/x', $installed.ProductCode, '/qn', '/norestart', 'REBOOT=ReallySuppress')
    if ($exit -notin @(0, 1605, 1641, 3010)) { Stop-Rmm 41 "uninstall_failed msiexec=$exit" }
    Write-Result 'ok' 0 'uninstalled' ''
}

# Sets $script:ExitCode; the output of the actions stays in the pipeline.
function Invoke-Rmm {
    $script:ExitCode = 0
    try {
        switch ($Action) {
            'Install' { Invoke-Install }
            'SetEnrollmentKey' { Invoke-SetEnrollmentKey }
            'Uninstall' { Invoke-Uninstall }
        }
    }
    catch {
        if ($_.Exception.Data.Contains('RmmCode')) {
            $code = [int]$_.Exception.Data['RmmCode']
            $reason = [string]$_.Exception.Data['RmmReason']
            $extra = ''
            if ($reason -match '^(\w+) (msiexec=\d+)$') { $reason = $Matches[1]; $extra = $Matches[2] }
            $result = 'refused'
            if ($code -in @(35, 40, 41, 52)) { $result = 'failed' }
            Write-Result $result $code $reason $extra
            $script:ExitCode = $code
        }
        else {
            # the type only: the message of an unexpected exception can contain a path, a URL or a value
            Write-Result 'failed' 60 'unexpected' ('type=' + $_.Exception.GetType().Name)
            $script:ExitCode = 60
        }
    }
}

# Dot-sourcing (the tests) loads the functions only; a run by the RMM executes the action.
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-Rmm
    exit $script:ExitCode
}
