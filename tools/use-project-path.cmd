@echo off
set "SCRIPTUREFORGE_ROOT=%~dp0.."
for %%I in ("%SCRIPTUREFORGE_ROOT%") do set "SCRIPTUREFORGE_ROOT=%%~fI"

if exist "%SCRIPTUREFORGE_ROOT%\.tools\go\bin" set "PATH=%SCRIPTUREFORGE_ROOT%\.tools\go\bin;%PATH%"
if exist "%SCRIPTUREFORGE_ROOT%\.tools\cargo\bin" set "PATH=%SCRIPTUREFORGE_ROOT%\.tools\cargo\bin;%PATH%"
if exist "%SCRIPTUREFORGE_ROOT%\.tools\terraform" set "PATH=%SCRIPTUREFORGE_ROOT%\.tools\terraform;%PATH%"
if exist "%SCRIPTUREFORGE_ROOT%\.tools\bin" set "PATH=%SCRIPTUREFORGE_ROOT%\.tools\bin;%PATH%"
if exist "%SCRIPTUREFORGE_ROOT%\.tools\rustup\toolchains\stable-x86_64-pc-windows-msvc\bin" (
  set "PATH=%SCRIPTUREFORGE_ROOT%\.tools\rustup\toolchains\stable-x86_64-pc-windows-msvc\bin;%PATH%"
)
for /d %%D in ("%SCRIPTUREFORGE_ROOT%\.tools\rustup\toolchains\*") do (
  if exist "%%~fD\bin" set "PATH=%%~fD\bin;%PATH%"
)
if exist "%USERPROFILE%\.cargo\bin" set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
for %%I in ("%USERPROFILE%") do set "SCRIPTUREFORGE_USERPROFILE=%%~fI"
if exist "%SCRIPTUREFORGE_USERPROFILE%\.local\bin" set "PATH=%SCRIPTUREFORGE_USERPROFILE%\.local\bin;%PATH%"
if exist "C:\Users\domin\.local\bin" set "PATH=C:\Users\domin\.local\bin;%PATH%"
if exist "%USERPROFILE%\go\bin" set "PATH=%USERPROFILE%\go\bin;%PATH%"
if exist "%SCRIPTUREFORGE_USERPROFILE%\go\bin" set "PATH=%SCRIPTUREFORGE_USERPROFILE%\go\bin;%PATH%"
if exist "%HOMEDRIVE%%HOMEPATH%\go\bin" set "PATH=%HOMEDRIVE%%HOMEPATH%\go\bin;%PATH%"
if exist "C:\Users\domin\go\bin" set "PATH=C:\Users\domin\go\bin;%PATH%"
if exist "%ProgramFiles%\GitHub CLI" set "PATH=%ProgramFiles%\GitHub CLI;%PATH%"
if exist "%ProgramFiles(x86)%\GitHub CLI" set "PATH=%ProgramFiles(x86)%\GitHub CLI;%PATH%"
if exist "C:\Program Files\Amazon\AWSCLIV2" set "PATH=C:\Program Files\Amazon\AWSCLIV2;%PATH%"
if exist "C:\Program Files (x86)\Amazon\AWSCLIV2" set "PATH=C:\Program Files (x86)\Amazon\AWSCLIV2;%PATH%"
if exist "%LOCALAPPDATA%\Microsoft\WinGet\Links" set "PATH=%LOCALAPPDATA%\Microsoft\WinGet\Links;%PATH%"
if exist "%ChocolateyInstall%\bin" set "PATH=%ChocolateyInstall%\bin;%PATH%"
if exist "C:\ProgramData\chocolatey\bin" set "PATH=C:\ProgramData\chocolatey\bin;%PATH%"
if exist "%USERPROFILE%\scoop\shims" set "PATH=%USERPROFILE%\scoop\shims;%PATH%"
if exist "C:\Program Files\PostgreSQL\18\bin" set "PATH=C:\Program Files\PostgreSQL\18\bin;%PATH%"
if exist "C:\Program Files\PostgreSQL\17\bin" set "PATH=C:\Program Files\PostgreSQL\17\bin;%PATH%"
if exist "C:\Program Files\PostgreSQL\16\bin" set "PATH=C:\Program Files\PostgreSQL\16\bin;%PATH%"
if exist "C:\Program Files\PostgreSQL\15\bin" set "PATH=C:\Program Files\PostgreSQL\15\bin;%PATH%"
if exist "C:\Program Files\PostgreSQL\14\bin" set "PATH=C:\Program Files\PostgreSQL\14\bin;%PATH%"
if exist "C:\Program Files\PostgreSQL\13\bin" set "PATH=C:\Program Files\PostgreSQL\13\bin;%PATH%"
if exist "C:\Program Files\PostgreSQL\12\bin" set "PATH=C:\Program Files\PostgreSQL\12\bin;%PATH%"
if exist "C:\Program Files (x86)\PostgreSQL\18\bin" set "PATH=C:\Program Files (x86)\PostgreSQL\18\bin;%PATH%"
if exist "C:\Program Files (x86)\PostgreSQL\17\bin" set "PATH=C:\Program Files (x86)\PostgreSQL\17\bin;%PATH%"
if exist "C:\Program Files (x86)\PostgreSQL\16\bin" set "PATH=C:\Program Files (x86)\PostgreSQL\16\bin;%PATH%"
if exist "C:\Program Files (x86)\PostgreSQL\15\bin" set "PATH=C:\Program Files (x86)\PostgreSQL\15\bin;%PATH%"
if exist "C:\Program Files (x86)\PostgreSQL\14\bin" set "PATH=C:\Program Files (x86)\PostgreSQL\14\bin;%PATH%"
if exist "C:\Program Files (x86)\PostgreSQL\13\bin" set "PATH=C:\Program Files (x86)\PostgreSQL\13\bin;%PATH%"
if exist "C:\Program Files (x86)\PostgreSQL\12\bin" set "PATH=C:\Program Files (x86)\PostgreSQL\12\bin;%PATH%"
set "SCRIPTUREFORGE_COMBINED_PATH=%PATH%"
set "PATH="
set "Path=%SCRIPTUREFORGE_COMBINED_PATH%"

set "CARGO_HOME=%SCRIPTUREFORGE_ROOT%\.tools\cargo"
set "RUSTUP_HOME=%SCRIPTUREFORGE_ROOT%\.tools\rustup"

echo ScriptureForgeAI project PATH is active for this cmd shell.
if not "%~1"=="" (
  if /I not "%~1"=="--strict-staging" if /I not "%~1"=="--staging-evidence" (
    call %*
    exit /b %ERRORLEVEL%
  )
)
if exist "%SCRIPTUREFORGE_ROOT%\tools\verify-project-path.mjs" (
  if /I "%~1"=="--strict-staging" (
    node "%SCRIPTUREFORGE_ROOT%\tools\verify-project-path.mjs" --strict-staging
    if errorlevel 1 exit /b 1
    exit /b 0
  ) else if /I "%~1"=="--staging-evidence" (
    node "%SCRIPTUREFORGE_ROOT%\tools\verify-project-path.mjs" --strict-staging
    if errorlevel 1 exit /b 1
    exit /b 0
  ) else (
    node "%SCRIPTUREFORGE_ROOT%\tools\verify-project-path.mjs"
    if errorlevel 1 exit /b 1
    exit /b 0
  )
) else (
  where rtk 2>nul
  where git 2>nul
  where go 2>nul
  where node 2>nul
  where npm 2>nul
  where cargo 2>nul
  where rustc 2>nul
  where terraform 2>nul
  echo protoc is optional; Rust build uses protoc-bin-vendored.
  echo psql is optional for local manual DB work; CI installs postgresql-client.
)
if errorlevel 1 exit /b 1
exit /b 0
