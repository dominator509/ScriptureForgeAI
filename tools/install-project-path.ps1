param(
  [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$homeProfile = [Environment]::GetFolderPath("UserProfile")
$localAppData = [Environment]::GetFolderPath("LocalApplicationData")

$candidateEntries = @(
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
  (Join-Path $localAppData "Microsoft\WinGet\Links"),
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
) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

$existingUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$existingEntries = @($existingUserPath -split ";" | Where-Object { $_ -ne "" })
$existingLookup = @{}
foreach ($entry in $existingEntries) {
  $existingLookup[$entry.TrimEnd("\").ToLowerInvariant()] = $true
}

$missingEntries = @()
foreach ($entry in $candidateEntries) {
  $key = $entry.TrimEnd("\").ToLowerInvariant()
  if (-not $existingLookup.ContainsKey($key)) {
    $missingEntries += $entry
  }
}

if ($missingEntries.Count -eq 0) {
  Write-Host "ScriptureForgeAI user PATH already includes all discovered project tool directories."
  exit 0
}

Write-Host "ScriptureForgeAI user PATH entries to add:"
foreach ($entry in $missingEntries) {
  Write-Host "- $entry"
}

if ($WhatIf) {
  Write-Host "WhatIf: no user PATH changes were written."
  exit 0
}

$newEntries = @($missingEntries + $existingEntries)
$newUserPath = ($newEntries | Where-Object { $_ -ne "" } | Select-Object -Unique) -join ";"
[Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")

$persistedUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$persistedLookup = @{}
foreach ($entry in @($persistedUserPath -split ";" | Where-Object { $_ -ne "" })) {
  $persistedLookup[$entry.TrimEnd("\").ToLowerInvariant()] = $true
}

$unpersistedEntries = @()
foreach ($entry in $missingEntries) {
  $key = $entry.TrimEnd("\").ToLowerInvariant()
  if (-not $persistedLookup.ContainsKey($key)) {
    $unpersistedEntries += $entry
  }
}

if ($unpersistedEntries.Count -gt 0) {
  Write-Error ("Windows user PATH update did not persist these entries: {0}" -f ($unpersistedEntries -join "; "))
  exit 1
}

Write-Host "Updated the Windows user PATH. Open a new terminal or restart GUI tools to pick it up."
