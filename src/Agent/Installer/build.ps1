#Requires -Version 5.1
# Builds Sikkerheit.Agent.msi on Windows (WP-11). Needs the WiX CLI (v4-v7; the EULA of v7 is accepted by the owner, 08 question 8)
# with the Util extension. The MSI is signed afterwards by the signing step of the CI (Artifact Signing); this script does not sign.
param(
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [Parameter(Mandatory)][string]$Manufacturer,
    [Parameter(Mandatory)][string]$ServerUrl,
    [string]$Output = (Join-Path $PSScriptRoot 'out\Sikkerheit.Agent.msi')
)
$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot '..\Sikkerheit.Agent\Sikkerheit.Agent.csproj'
$publish = Join-Path $PSScriptRoot 'out\publish'
dotnet publish $project -c Release -r win-x64 --self-contained true -p:Version=$Version -o $publish
if ($LASTEXITCODE -ne 0) { throw 'dotnet publish failed' }
wix extension add -g WixToolset.Util.wixext
wix build (Join-Path $PSScriptRoot 'Package.wxs') -arch x64 -ext WixToolset.Util.wixext `
    -d Version=$Version -d Manufacturer=$Manufacturer -d ServerUrl=$ServerUrl -d PublishDir=$publish -o $Output
if ($LASTEXITCODE -ne 0) { throw 'wix build failed' }
Write-Output "built $Output"
