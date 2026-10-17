#Requires -Version 5.1
# The release gate runs on Windows after both signing steps. It never installs the candidate.
param(
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [Parameter(Mandatory)][string]$PublisherCommonName,
    [Parameter(Mandatory)][string]$PublisherOrganization,
    [string]$Directory = (Join-Path $PSScriptRoot '..\..\src\Agent\Installer\out')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# The standalone RMM uses the same DN rules: quoted/escaped commas, exactly one CN and one O, case-sensitive values.
function Read-Subject([string]$Subject) {
    $parts = New-Object System.Collections.Generic.List[string]
    $text = New-Object System.Text.StringBuilder
    $quoted = $false
    $escaped = $false
    foreach ($ch in $Subject.ToCharArray()) {
        if ($escaped) { [void]$text.Append($ch); $escaped = $false; continue }
        if ($ch -eq '\') { $escaped = $true; continue }
        if ($ch -eq '"') { $quoted = -not $quoted; continue }
        if ($ch -eq ',' -and -not $quoted) { $parts.Add($text.ToString()); [void]$text.Clear(); continue }
        [void]$text.Append($ch)
    }
    if ($quoted -or $escaped) { throw 'Invalid publisher subject' }
    $parts.Add($text.ToString())
    $pairs = @($parts | ForEach-Object {
        $at = $_.IndexOf('=')
        if ($at -gt 0) { [pscustomobject]@{ Name = $_.Substring(0, $at).Trim(); Value = $_.Substring($at + 1).Trim() } }
    })
    $cn = @($pairs | Where-Object { $_.Name -eq 'CN' })
    $org = @($pairs | Where-Object { $_.Name -eq 'O' })
    if ($cn.Count -ne 1 -or $org.Count -ne 1 -or $cn[0].Value -cne $PublisherCommonName -or $org[0].Value -cne $PublisherOrganization) {
        throw 'Unexpected release publisher'
    }
}

$msi = Join-Path $Directory 'Sikkerheit.Agent.msi'
$payload = @(Get-ChildItem (Join-Path $Directory 'publish') -File | Where-Object { $_.Name -like 'Sikkerheit*' -and $_.Extension -in '.exe', '.dll' })
if ($payload.Count -lt 3 -or -not (Test-Path $msi)) { throw 'Release files are missing' }
foreach ($file in @($msi) + @($payload.FullName)) {
    $signature = Get-AuthenticodeSignature -LiteralPath $file
    if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or $null -eq $signature.TimeStamperCertificate) {
        throw 'Release signature or timestamp is invalid'
    }
    Read-Subject $signature.SignerCertificate.Subject
}
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.OpenDatabase((Resolve-Path $msi).Path, 0)
$view = $database.OpenView("SELECT Value FROM Property WHERE Property='ProductVersion'")
$view.Execute()
$record = $view.Fetch()
if ($record.StringData(1) -cne $Version) { throw 'MSI version does not match the approved candidate' }
$view.Close()
$commit = git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot identify the source commit' }
$manifest = [ordered]@{
    version = $Version
    sha256 = (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant()
    publisherCommonName = $PublisherCommonName
    publisherOrganization = $PublisherOrganization
    sourceCommit = $commit
    createdAt = [DateTime]::UtcNow.ToString('o')
    status = 'candidate_requires_SP04_SP05_and_pilot_acceptance'
}
$manifest | ConvertTo-Json | Set-Content (Join-Path $Directory 'release.json') -Encoding UTF8
Write-Output 'Release signatures, publisher, timestamp and MSI version verified; candidate manifest created.'
