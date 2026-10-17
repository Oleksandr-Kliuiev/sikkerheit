#Requires -Version 5.1
# Builds Sikkerheit.Agent.msi on Windows (WP-11). Needs the WiX CLI (v4-v7; the EULA of v7 is accepted by the owner, 08 question 8)
# with the Util extension. The MSI is signed afterwards by the signing step of the CI (Artifact Signing); this script does not sign.
param(
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [Parameter(Mandatory)][string]$Manufacturer,
    [Parameter(Mandatory)][string]$ServerUrl,
    [string]$Output = (Join-Path $PSScriptRoot 'out\Sikkerheit.Agent.msi'),
    [ValidatePattern('^7\.\d+\.\d+$')][string]$WixVersion = '7.0.0',
    [switch]$PublishOnly,
    [switch]$PackageOnly
)
$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot '..\Sikkerheit.Agent\Sikkerheit.Agent.csproj'
$publish = Join-Path $PSScriptRoot 'out\publish'
if ($PublishOnly -and $PackageOnly) { throw 'Choose PublishOnly or PackageOnly' }
if (-not $PackageOnly) {
    if (Test-Path $publish) { Remove-Item $publish -Recurse -Force }
    dotnet publish $project -c Release -r win-x64 --self-contained true -p:Version=$Version -o $publish
    if ($LASTEXITCODE -ne 0) { throw 'dotnet publish failed' }
}
if ($PublishOnly) { Write-Output "published $publish"; exit 0 }
if (-not (Test-Path (Join-Path $publish 'Sikkerheit.Agent.exe'))) { throw 'Publish the agent before packaging' }
$installed = (wix --version | Select-Object -First 1).Trim()
if ($LASTEXITCODE -ne 0 -or -not $installed.StartsWith($WixVersion + '+') -and $installed -ne $WixVersion) {
    throw 'Installed WiX does not match WixVersion'
}
wix extension add -g "WixToolset.Util.wixext/$WixVersion"
if ($LASTEXITCODE -ne 0) { throw 'WiX extension installation failed' }
wix build (Join-Path $PSScriptRoot 'Package.wxs') -arch x64 -ext WixToolset.Util.wixext `
    -d Version=$Version -d Manufacturer=$Manufacturer -d ServerUrl=$ServerUrl -d PublishDir=$publish -o $Output
if ($LASTEXITCODE -ne 0) { throw 'wix build failed' }
wix msi validate $Output
if ($LASTEXITCODE -ne 0) { throw 'MSI validation failed' }
Write-Output "built $Output"
