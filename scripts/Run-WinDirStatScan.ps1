<#
.SYNOPSIS
    Downloads WinDirStat, extracts it, scans the C: drive and saves the report to CSV.

.DESCRIPTION
    Downloads the WinDirStat release archive, extracts it, then runs
    WinDirStat.exe with /SaveTo to write a scan report of the target drive
    to the requested CSV path.
#>

[CmdletBinding()]
param(
    [string]$DownloadUrl = 'https://github.com/windirstat/windirstat/releases/download/beta%2Fv2.7.2%2F2026-07-22/WinDirStat.zip',
    [string]$ScanPath = 'C:\',
    [string]$ReportPath = 'C:\Reports\scan.csv'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) 'windirstat'
$zipPath = Join-Path $workDir 'WinDirStat.zip'
$extractDir = Join-Path $workDir 'extracted'

New-Item -ItemType Directory -Path $workDir -Force | Out-Null
if (Test-Path -LiteralPath $extractDir) {
    Remove-Item -LiteralPath $extractDir -Recurse -Force
}
New-Item -ItemType Directory -Path $extractDir -Force | Out-Null

Write-Host "Downloading WinDirStat from $DownloadUrl"
Invoke-WebRequest -Uri $DownloadUrl -OutFile $zipPath

Write-Host "Extracting archive to $extractDir"
Expand-Archive -LiteralPath $zipPath -DestinationPath $extractDir -Force

$exePath = Join-Path $extractDir 'x64\WinDirStat.exe'
if (-not (Test-Path -LiteralPath $exePath)) {
    throw "WinDirStat.exe was not found at expected path: $exePath"
}

$reportDir = Split-Path -Path $ReportPath -Parent
if ($reportDir -and -not (Test-Path -LiteralPath $reportDir)) {
    New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
}

Write-Host "Running scan: `"$exePath`" /SaveTo `"$ReportPath`" `"$ScanPath`""
$process = Start-Process -FilePath $exePath -ArgumentList @('/SaveTo', $ReportPath, $ScanPath) -Wait -PassThru
Write-Host "WinDirStat exited with code $($process.ExitCode)"

if (-not (Test-Path -LiteralPath $ReportPath)) {
    throw "Scan report was not created at: $ReportPath"
}

Write-Host "Scan report saved to $ReportPath"
