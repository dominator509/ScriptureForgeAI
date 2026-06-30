param(
  [switch]$Quiet,
  [switch]$StrictStaging,
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$Command
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$homeProfile = [Environment]::GetFolderPath("UserProfile")
$localAppData = if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Links" } else { $null }
$chocolateyBin = if ($env:ChocolateyInstall) { Join-Path $env:ChocolateyInstall "bin" } else { $null }
$pathEntries = @(
  (Join-Path $repoRoot ".tools\go\bin"),
  (Join-Path $repoRoot ".tools\cargo\bin"),
  (Join-Path $repoRoot ".tools\terraform"),
  (Join-Path $repoRoot ".tools\bin"),
  (Join-Path $homeProfile ".local\bin"),
  "C:\Users\domin\.local\bin",
  (Join-Path $env:USERPROFILE "go\bin"),
  (Join-Path $homeProfile "go\bin"),
  "C:\Users\domin\go\bin",
  "C:\Program Files\GitHub CLI",
  "C:\Program Files (x86)\GitHub CLI",
  "C:\Program Files\Amazon\AWSCLIV2",
  "C:\Program Files (x86)\Amazon\AWSCLIV2",
  $localAppData,
  $chocolateyBin,
  "C:\ProgramData\chocolatey\bin",
  (Join-Path $homeProfile "scoop\shims"),
  "C:\Program Files\PostgreSQL\18\bin",
  "C:\Program Files\PostgreSQL\17\bin",
  "C:\Program Files\PostgreSQL\16\bin",
  "C:\Program Files\PostgreSQL\15\bin",
  "C:\Program Files\PostgreSQL\14\bin",
  "C:\Program Files\PostgreSQL\13\bin",
  "C:\Program Files\PostgreSQL\12\bin",
  "C:\Program Files (x86)\PostgreSQL\18\bin",
  "C:\Program Files (x86)\PostgreSQL\17\bin",
  "C:\Program Files (x86)\PostgreSQL\16\bin",
  "C:\Program Files (x86)\PostgreSQL\15\bin",
  "C:\Program Files (x86)\PostgreSQL\14\bin",
  "C:\Program Files (x86)\PostgreSQL\13\bin",
  "C:\Program Files (x86)\PostgreSQL\12\bin"
) | Where-Object { Test-Path -LiteralPath $_ }

$currentEntries = @($env:Path -split ";" | Where-Object { $_ -ne "" })
$orderedPathEntries = [array]$pathEntries.Clone()
[array]::Reverse($orderedPathEntries)
foreach ($entry in $orderedPathEntries) {
  if ($currentEntries -notcontains $entry) {
    $env:Path = "$entry;$env:Path"
  }
}
$env:PATH = $env:Path

$env:CARGO_HOME = Join-Path $repoRoot ".tools\cargo"
$env:RUSTUP_HOME = Join-Path $repoRoot ".tools\rustup"

if ($Command.Count -gt 0) {
  & $Command[0] @($Command | Select-Object -Skip 1)
  if ($null -ne $LASTEXITCODE) {
    exit $LASTEXITCODE
  }
  exit 0
}

if (-not $Quiet) {
  Write-Host "ScriptureForgeAI project PATH is active for this shell."
  $verifier = Join-Path $repoRoot "tools\verify-project-path.mjs"
  if (Test-Path -LiteralPath $verifier) {
    $verifierArgs = @($verifier)
    if ($StrictStaging) {
      $verifierArgs += "--strict-staging"
    }
    node @verifierArgs
    if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) {
      exit $LASTEXITCODE
    }
  } else {
    foreach ($command in @("rtk", "git", "go", "node", "npm", "cargo", "rustc", "terraform")) {
      $resolved = Get-Command $command -ErrorAction SilentlyContinue
      if ($resolved) {
        Write-Host ("{0}: {1}" -f $command, $resolved.Source)
      } else {
        Write-Host ("{0}: <missing>" -f $command)
      }
    }
    Write-Host "protoc: optional; Rust build uses protoc-bin-vendored."
    Write-Host "psql: optional for local manual DB work; CI installs postgresql-client."
  }
}
