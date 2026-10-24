<#
.SYNOPSIS
  One-time lab setup for AI Security Engineer (The Sec Guy), for Windows 10 22H2 / Windows 11.

.DESCRIPTION
  What it does, in order (it asks before every install, and you can say no):
    1. Looks at this computer: Windows version, CPU, memory, free disk, signs of a work-managed laptop,
       and whether WSL 2 and hardware virtualisation (needed by Docker Desktop) are ready.
    2. Installs what is missing with winget (Windows' own package manager): git, Python 3.13,
       Docker Desktop, Ollama. If WSL 2 is missing it turns it on, asks you to restart Windows,
       and remembers where it stopped: run the same command again after the restart.
    3. Starts Ollama on 127.0.0.1 (never 0.0.0.0) and downloads the two lab models (sizes shown first).
    4. Creates ONE shared Python virtual environment, .venv, at the repo root.
    5. Runs tools\doctor.py, which prints [ok] / [XX] per item with the exact next step.

  Safe to run again: it skips whatever is already done. No telemetry. Everything is logged to setup.log.
  Administrator rights are needed only by the installers that ask for them (Windows shows its own prompt).

  Run it from the repo folder in PowerShell:
    powershell -ExecutionPolicy Bypass -File setup.ps1
  -ExecutionPolicy Bypass applies to this one run only; it does not change your computer's policy.

.PARAMETER Yes        Answer yes to every install question.
.PARAMETER Check      Look only: report what is missing, change nothing.
.PARAMETER Uninstall  Remove what this script made in the repo (.venv folders, the lab models).
.PARAMETER NoDocker   Skip Docker.
.PARAMETER NoOllama   Skip Ollama and the models.
.PARAMETER NoModels   Skip the model downloads.
.LINK docs/SETUP.md
#>
[CmdletBinding()]
param(
    [switch]$Yes,
    [switch]$Check,
    [switch]$Uninstall,
    [switch]$NoDocker,
    [switch]$NoOllama,
    [switch]$NoModels
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$Root      = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogFile   = Join-Path $Root 'setup.log'
$StateFile = Join-Path $Root '.setup-state.json'
$Venv      = Join-Path $Root '.venv'
$VenvPy    = Join-Path $Venv 'Scripts\python.exe'
$Reqs      = Join-Path $Root 'requirements-common.txt'
$OllamaApi = 'http://127.0.0.1:11434'
$Models    = @(
    @{ Name = 'gemma3:1b';      Size = 'about 806 MB' },
    @{ Name = 'embeddinggemma'; Size = 'about 622 MB' }
)
$MinRamGB  = 8
$MinDiskGB = 15
if ($NoOllama) { $NoModels = $true }
$script:Python = $null   # array: executable + arguments, e.g. @('py', '-3.13')

# ------------------------------------------------------------------ output, log, questions

function Write-Log([string]$Text) {
    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Text
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch { }
}
function Say([string]$Text)  { Write-Host $Text; Write-Log $Text }
function Step([string]$Text) { Write-Host ''; Write-Host "== $Text" -ForegroundColor White; Write-Log "== $Text" }
function Ok([string]$Text)   { Write-Host '  [ok] ' -ForegroundColor Green -NoNewline; Write-Host $Text; Write-Log "ok: $Text" }
function Warn([string]$Text) { Write-Host '  [!!] ' -ForegroundColor Yellow -NoNewline; Write-Host $Text; Write-Log "warn: $Text" }
function Bad([string]$Text)  { Write-Host '  [XX] ' -ForegroundColor Red -NoNewline; Write-Host $Text; Write-Log "missing: $Text" }

# Ask a yes/no question. -Yes answers default-yes questions with yes; default-no questions stay no.
function Ask([string]$Question, [bool]$DefaultYes = $true) {
    $hint = '[Y/n]'
    if (-not $DefaultYes) { $hint = '[y/N]' }
    if ($Yes) {
        if ($DefaultYes) { Say "  $Question $hint y (-Yes)"; return $true }
        Say "  $Question $hint n (-Yes keeps the safe answer here)"; return $false
    }
    try { $reply = Read-Host "  $Question $hint" }
    catch { Say "  $Question $hint no one to ask, so: no (use -Yes to accept)"; return $false }
    Write-Log "ask: $Question -> $reply"
    if ([string]::IsNullOrWhiteSpace($reply)) { return $DefaultYes }
    return ($reply -match '^(y|yes)$')
}

# Run a program with live output; log the command and its exit code. Returns the exit code.
function Invoke-Logged([string]$Exe, [string[]]$Arguments) {
    Write-Host ('  $ {0} {1}' -f $Exe, ($Arguments -join ' ')) -ForegroundColor White
    Write-Log ('run: {0} {1}' -f $Exe, ($Arguments -join ' '))
    & $Exe @Arguments
    $code = $LASTEXITCODE
    if ($null -eq $code) { $code = 0 }
    if ($code -ne 0) { Write-Log "exit code $code" }
    return $code
}

function Test-Command([string]$Name) { return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }

function Update-SessionPath {
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = "$machine;$user"
}

function Save-State([string]$Pending) {
    @{ pending = $Pending; saved = (Get-Date -Format 's') } | ConvertTo-Json | Set-Content -Path $StateFile -Encoding UTF8
}
function Read-State {
    if (Test-Path $StateFile) {
        try { return (Get-Content $StateFile -Raw | ConvertFrom-Json) } catch { return $null }
    }
    return $null
}

# ------------------------------------------------------------------ 1. this computer

function Show-System {
    Step '1. This computer'
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $build = [int]$os.BuildNumber
    $arch = $env:PROCESSOR_ARCHITECTURE
    if ($build -lt 19045) {
        Warn ("{0} (build {1}). Docker Desktop and Ollama need Windows 10 22H2 (build 19045) or newer: run Windows Update first." -f $os.Caption, $build)
    } else {
        Ok ("{0} (build {1}, {2})" -f $os.Caption, $build, $arch)
    }
    $ramGB = [math]::Round($cs.TotalPhysicalMemory / 1GB)
    if ($ramGB -lt $MinRamGB) { Warn "Memory: $ramGB GB. Below $MinRamGB GB the labs still run (most use a stand-in model), but close other apps when a real model runs." }
    else { Ok "Memory: $ramGB GB" }
    $drive = (Get-Item $Root).PSDrive
    $freeGB = [math]::Floor($drive.Free / 1GB)
    if ($freeGB -lt $MinDiskGB) { Warn "Free disk on ${drive}: $freeGB GB. $MinDiskGB GB is comfortable (models about 1.4 GB, Docker images, lab packages)." }
    else { Ok "Free disk on ${drive}: $freeGB GB" }

    # Work laptop hints. Proxy values are never logged: they can contain a user name and password.
    $hints = @()
    if ($cs.PartOfDomain) { $hints += 'joined to a company domain' }
    try {
        $dsreg = (& dsregcmd.exe /status) 2>$null | Out-String
        if ($dsreg -match 'AzureAdJoined\s*:\s*YES') { $hints += 'joined to Microsoft Entra ID' }
    } catch { }
    if ($env:HTTPS_PROXY -or $env:HTTP_PROXY) { $hints += 'a proxy is set' }
    if ($hints.Count -gt 0) {
        Warn ("Looks like a work-managed computer: {0}." -f ($hints -join ', '))
        Warn "Installs may be blocked, and Docker Desktop may need a paid licence at a large company. Ask IT first. docs/SETUP.md, 'Work laptops'."
    }
}

# ------------------------------------------------------------------ 2. winget

function Test-Winget {
    if (Test-Command 'winget') { Ok 'winget (Windows package manager)'; return $true }
    Bad 'winget is missing. Install or update "App Installer" from the Microsoft Store, then run setup again.'
    Say '  Or install each tool by hand: lesson 0.6 lists the official download pages.'
    return $false
}

function Install-WithWinget([string]$Id, [string]$Label) {
    if (-not (Test-Command 'winget')) { Bad "cannot install $Label without winget"; return $false }
    if (-not (Ask "Install $Label with winget (package $Id)?")) { return $false }
    $code = Invoke-Logged 'winget' @('install', '--id', $Id, '--exact', '--source', 'winget',
                                      '--accept-package-agreements', '--accept-source-agreements')
    Update-SessionPath
    # winget returns non-zero for "already installed" and similar; the caller re-checks the tool itself.
    if ($code -ne 0) { Write-Log "winget exit code $code for $Id" }
    return $true
}

# ------------------------------------------------------------------ 3. git

function Confirm-Git {
    Step '2. git'
    if (Test-Command 'git') { Ok ("git ({0})" -f ((& git --version) -join ' ')); return }
    Bad 'git'
    if ($Check) { return }
    if (Install-WithWinget 'Git.Git' 'Git for Windows') {
        if (Test-Command 'git') { Ok 'git installed' } else { Warn 'git installed: open a new PowerShell window so it is on PATH.' }
    }
}

# ------------------------------------------------------------------ 4. Python 3.11+

function Get-PythonVersion([string[]]$Cmd) {
    $exe = $Cmd[0]
    $rest = @()
    if ($Cmd.Count -gt 1) { $rest = $Cmd[1..($Cmd.Count - 1)] }
    try {
        $out = (& $exe @rest -c 'import sys; print("%d.%d" % sys.version_info[:2])') 2>$null
        if ($LASTEXITCODE -eq 0 -and $out -match '^3\.\d+$') { return [string]$out }
    } catch { }
    return $null
}

# Best Python for the labs: 3.13 (every lab is tested on it), then 3.12, 3.11, then newer.
function Find-Python {
    $candidates = @()
    if (Test-Command 'py') { $candidates += ,@('py', '-3.13'); $candidates += ,@('py', '-3.12'); $candidates += ,@('py', '-3.11') }
    foreach ($v in @('313', '312', '311')) {
        foreach ($base in @("$env:LOCALAPPDATA\Programs\Python", $env:ProgramFiles)) {
            $p = Join-Path $base "Python$v\python.exe"
            if (Test-Path $p) { $candidates += ,@($p) }
        }
    }
    # 'python' may be the Microsoft Store stub, which prints nothing: Get-PythonVersion filters it out.
    if (Test-Command 'python') { $candidates += ,@('python') }
    if (Test-Command 'py') { $candidates += ,@('py', '-3') }
    $best = $null; $bestScore = 0
    foreach ($c in $candidates) {
        $ver = Get-PythonVersion $c
        if (-not $ver) { continue }
        $minor = [int]($ver.Split('.')[1])
        $score = 0
        if ($minor -eq 13) { $score = 50 } elseif ($minor -eq 12) { $score = 40 } elseif ($minor -eq 11) { $score = 30 } elseif ($minor -gt 13) { $score = 20 }
        if ($score -gt $bestScore) { $best = $c; $bestScore = $score }
    }
    $script:Python = $best
    return ($null -ne $best)
}

function Confirm-Python {
    Step '3. Python 3.11 or newer'
    if (Find-Python) { Ok ("Python {0} ({1})" -f (Get-PythonVersion $script:Python), ($script:Python -join ' ')); return }
    Bad 'Python 3.11 or newer'
    if ($Check) { return }
    if (Install-WithWinget 'Python.Python.3.13' 'Python 3.13') {
        if (Find-Python) { Ok ("Python {0} installed" -f (Get-PythonVersion $script:Python)) }
        else { Warn 'Python installed: open a new PowerShell window and run setup again.' }
    }
}

# ------------------------------------------------------------------ 5. WSL 2 + Docker

function Test-Wsl {
    try { & wsl.exe --status *> $null; return ($LASTEXITCODE -eq 0) } catch { return $false }
}

function Test-Virtualisation {
    try {
        $cs = Get-CimInstance Win32_ComputerSystem
        if ($cs.HypervisorPresent) { return $true }
        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
        return [bool]$cpu.VirtualizationFirmwareEnabled
    } catch { return $true }   # cannot tell: do not block
}

function Test-DockerEngine {
    if (-not (Test-Command 'docker')) { return $false }
    & docker info *> $null
    return ($LASTEXITCODE -eq 0)
}

function Start-DockerDesktop {
    if (Test-DockerEngine) { Ok 'Docker engine running'; return $true }
    if ($Check) { Bad 'Docker engine is not running (start Docker Desktop)'; return $false }
    $exe = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
    if (Test-Path $exe) {
        Say '  Starting Docker Desktop (accept the agreement in its window the first time)...'
        Start-Process -FilePath $exe | Out-Null
    }
    for ($i = 1; $i -le 60; $i++) {
        if (Test-DockerEngine) { Ok 'Docker engine running'; return $true }
        if ($i % 10 -eq 0) { Say ("  waiting for the Docker engine ({0} s)..." -f ($i * 3)) }
        Start-Sleep -Seconds 3
    }
    Warn 'Docker Desktop is installed but the engine is not answering yet. Start it from the Start menu; doctor checks again.'
    return $false
}

# Returns $false when the script must stop for a restart.
function Confirm-Docker {
    Step '4. Docker Desktop (runs lab apps in throwaway containers)'
    if ($NoDocker) { Warn 'skipped (-NoDocker)'; return $true }
    if (Test-Command 'docker') {
        Ok ("Docker installed ({0})" -f ((& docker --version) -join ' '))
        [void](Start-DockerDesktop)
        return $true
    }
    Bad 'Docker'
    if (-not (Test-Virtualisation)) {
        Warn 'Hardware virtualisation looks OFF. Docker Desktop needs it: turn on "Intel VT-x" / "AMD-V" / "SVM" in your BIOS/UEFI settings (docs/SETUP.md, "Virtualisation").'
    }
    if (-not (Test-Wsl)) {
        Bad 'WSL 2 (Windows Subsystem for Linux), which Docker Desktop uses'
        if ($Check) { return $true }
        $state = Read-State
        if ($state -and $state.pending -eq 'wsl-restart') {
            Warn 'Setup already turned WSL on earlier. Restart Windows if you have not yet; if you did, see docs/SETUP.md, "WSL".'
        }
        if (Ask 'Turn on WSL 2 now? Windows asks for administrator rights, then you restart') {
            Write-Log 'run: wsl.exe --install --no-distribution (as administrator)'
            try {
                $p = Start-Process -FilePath 'wsl.exe' -ArgumentList '--install', '--no-distribution' -Verb RunAs -Wait -PassThru
                Write-Log ("wsl --install exit code {0}" -f $p.ExitCode)
            } catch {
                Bad "Could not start the WSL installer: $($_.Exception.Message)"
                return $true
            }
            Save-State 'wsl-restart'
            Say ''
            Say 'WSL 2 is being turned on. RESTART WINDOWS now, then run the same command again:'
            Say '  powershell -ExecutionPolicy Bypass -File setup.ps1'
            Say 'Setup remembers where it stopped (.setup-state.json) and carries on from Docker.'
            return $false
        }
        return $true
    }
    Ok 'WSL 2 is ready'
    if ($Check) { return $true }
    Say '  Docker Desktop is free for personal use, education, non-commercial open source and small businesses'
    Say '  (fewer than 250 employees AND under $10 million a year). Larger companies need a paid plan.'
    Say '  Terms change: check https://docs.docker.com/subscription/desktop-license/ before you accept.'
    if (Install-WithWinget 'Docker.DockerDesktop' 'Docker Desktop') {
        if (-not (Test-Command 'docker')) {
            $bin = Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin'
            if (Test-Path $bin) { $env:Path = "$env:Path;$bin" }
        }
        if (Test-Command 'docker') {
            [void](Start-DockerDesktop)
            Say '  If Docker says your user is not allowed, sign out of Windows and back in once (new docker-users group).'
        } else {
            Warn 'Docker Desktop installer finished: restart Windows if it asked you to, then run setup again.'
        }
    }
    return $true
}

# ------------------------------------------------------------------ 6. Ollama + models

function Test-Ollama {
    try { $null = Invoke-RestMethod -Uri "$OllamaApi/api/version" -TimeoutSec 2; return $true } catch { return $false }
}

function Test-OllamaHostSetting {
    foreach ($scope in @('Process', 'User', 'Machine')) {
        $v = [Environment]::GetEnvironmentVariable('OLLAMA_HOST', $scope)
        if ($v -and ($v -notmatch '^(https?://)?(127\.0\.0\.1|localhost)(:\d+)?/?$')) {
            Warn "OLLAMA_HOST is set ($scope). Ollama has no login: on 0.0.0.0 anyone on your network can use it."
            Warn 'Remove it: Start, "Edit environment variables for your account", delete OLLAMA_HOST, then restart Ollama (lesson 0.6, Step 5).'
        }
    }
}

function Wait-Ollama([int]$Tries) {
    for ($i = 1; $i -le $Tries; $i++) {
        if (Test-Ollama) { Ok "Ollama answering on $OllamaApi"; return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}

function Start-Ollama {
    if (Test-Ollama) { Ok "Ollama answering on $OllamaApi"; return $true }
    if ($Check) { Bad 'Ollama is not running'; return $false }
    Say '  Starting Ollama on 127.0.0.1:11434...'
    $app = Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama app.exe'
    $env:OLLAMA_HOST = $null   # this process and what it starts use the safe default, 127.0.0.1
    if (Test-Path $app) {
        Start-Process -FilePath $app | Out-Null
        if (Wait-Ollama 15) { return $true }
    }
    if (Test-Command 'ollama') {
        Say "  (running 'ollama serve' in a hidden window)"
        Start-Process -FilePath 'ollama' -ArgumentList 'serve' -WindowStyle Hidden | Out-Null
        if (Wait-Ollama 30) { return $true }
    }
    Bad 'Ollama did not start. Open it from the Start menu, or see docs/SETUP.md.'
    return $false
}

function Confirm-Ollama {
    Step '5. Ollama (runs AI models on this computer)'
    if ($NoOllama) { Warn 'skipped (-NoOllama)'; return }
    Test-OllamaHostSetting
    if (Test-Command 'ollama') { Ok ("Ollama installed ({0})" -f ((& ollama --version 2>$null) -join ' ')) }
    else {
        Bad 'Ollama'
        if ($Check) { return }
        if (-not (Install-WithWinget 'Ollama.Ollama' 'Ollama')) { return }
        if (-not (Test-Command 'ollama')) {
            $dir = Join-Path $env:LOCALAPPDATA 'Programs\Ollama'
            if (Test-Path (Join-Path $dir 'ollama.exe')) { $env:Path = "$env:Path;$dir" }
        }
        if (-not (Test-Command 'ollama')) { Warn 'Ollama installed: open a new PowerShell window and run setup again.'; return }
    }
    [void](Start-Ollama)
}

function Get-OllamaModels {
    try { return @((Invoke-RestMethod -Uri "$OllamaApi/api/tags" -TimeoutSec 5).models | ForEach-Object { $_.name }) }
    catch { return @() }
}

function Confirm-Models {
    Step '6. Lab models'
    if ($NoModels) { Warn 'skipped (-NoModels)'; return }
    if (-not (Test-Ollama)) { Bad 'Ollama is not running, so models cannot be checked'; return }
    $have = Get-OllamaModels
    $missing = @()
    foreach ($m in $Models) {
        if (($have -contains $m.Name) -or ($have -contains ($m.Name + ':latest'))) { Ok $m.Name }
        else { Bad ("{0} ({1})" -f $m.Name, $m.Size); $missing += $m.Name }
    }
    if ($missing.Count -eq 0 -or $Check) { return }
    Say "  gemma3:1b is the course's small chat model; embeddinggemma turns text into vectors (RAG labs)."
    $what = 'about 1.4 GB for both'
    if ($missing.Count -eq 1) { $what = ($Models | Where-Object { $_.Name -eq $missing[0] }).Size }
    if (-not (Ask ("Download {0} ({1})?" -f ($missing -join ' '), $what))) { return }
    $env:OLLAMA_HOST = $null
    foreach ($name in $missing) {
        if ((Invoke-Logged 'ollama' @('pull', $name)) -ne 0) { Bad "could not download $name (check your internet or proxy)"; return }
    }
}

# ------------------------------------------------------------------ 7. shared virtual environment

function Install-Common {
    if (-not (Test-Path $Reqs)) { return }
    $lines = Get-Content $Reqs | Where-Object { $_ -match '^\s*[A-Za-z0-9]' }
    if (-not $lines -or $Check) { return }
    if ((Invoke-Logged $VenvPy @('-m', 'pip', 'install', '--disable-pip-version-check', '-q', '-r', $Reqs)) -eq 0) { Ok 'common packages installed' }
}

function Confirm-Venv {
    Step '7. Shared Python environment (.venv)'
    if (Test-Path $VenvPy) {
        $ver = Get-PythonVersion @($VenvPy)
        if ($ver -and ([int]$ver.Split('.')[1] -ge 11)) {
            & $VenvPy -m pip --version *> $null
            if ($LASTEXITCODE -eq 0) { Ok ".venv exists (Python $ver)"; Install-Common; return }
        }
        Bad ".venv exists but is broken or too old (Python $ver)"
        if ($Check) { return }
        if (-not (Ask 'Delete .venv and make it again?')) { return }
        Remove-Item -Recurse -Force $Venv
    } else {
        Bad '.venv not created yet'
        if ($Check) { return }
    }
    if (-not $script:Python -and -not (Find-Python)) { Bad 'no Python 3.11+ to build .venv with'; return }
    $exe = $script:Python[0]
    $rest = @()
    if ($script:Python.Count -gt 1) { $rest = $script:Python[1..($script:Python.Count - 1)] }
    if ((Invoke-Logged $exe ($rest + @('-m', 'venv', $Venv))) -ne 0) { Bad 'could not create .venv'; return }
    Ok (".venv created with Python {0}" -f (Get-PythonVersion @($VenvPy)))
    Install-Common
}

# ------------------------------------------------------------------ uninstall

function Invoke-Uninstall {
    Step 'Remove what setup.ps1 made'
    if ((Test-Path $Venv) -and (Ask 'Delete the shared .venv folder?')) { Remove-Item -Recurse -Force $Venv; Ok '.venv deleted' }
    Get-ChildItem -Path (Join-Path $Root 'labs') -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $lv = Join-Path $_.FullName '.venv'
        if ((Test-Path $lv) -and (Ask ("Delete labs\{0}\.venv?" -f $_.Name))) { Remove-Item -Recurse -Force $lv }
    }
    if ((Test-Command 'ollama') -and (Test-Ollama)) {
        $have = Get-OllamaModels
        foreach ($m in $Models) {
            if ((($have -contains $m.Name) -or ($have -contains ($m.Name + ':latest'))) -and (Ask ("Delete the model {0}?" -f $m.Name))) {
                [void](Invoke-Logged 'ollama' @('rm', $m.Name))
            }
        }
    } else {
        Say '  Ollama is not running: to delete the models later, run: ollama rm gemma3:1b embeddinggemma'
    }
    if (Test-Path $StateFile) { Remove-Item -Force $StateFile }
    Say ''
    Say 'Left installed on purpose (you may use them for other things): Docker Desktop, Ollama, Python, git, WSL.'
    Say "To remove those too: Settings, Apps, Installed apps (docs/SETUP.md, 'Uninstall'). setup.log stays until you delete it."
}

# ------------------------------------------------------------------ main

Write-Log ("---- setup.ps1 start: Check={0} Yes={1} Uninstall={2} PowerShell {3}" -f $Check, $Yes, $Uninstall, $PSVersionTable.PSVersion)
Write-Host 'AI Security Engineer: lab setup' -ForegroundColor White
if ($Check) { Write-Host 'Check only: nothing is installed or changed.' }
Write-Host "Log: $LogFile"

$state = Read-State
if ($state -and $state.pending -eq 'wsl-restart' -and -not $Check -and -not $Uninstall) {
    if (Test-Wsl) { Say 'Welcome back: WSL 2 is ready now, carrying on.'; Remove-Item -Force $StateFile }
}

Show-System
if ($Uninstall) { Invoke-Uninstall; exit 0 }

$haveWinget = Test-Winget
Confirm-Git
Confirm-Python
if (-not (Confirm-Docker)) { Write-Log '---- stopped for a restart'; exit 3 }
Confirm-Ollama
Confirm-Models
Confirm-Venv

Step '8. Doctor: final check'
$skip = @()
if ($NoDocker) { $skip += 'docker' }
if ($NoOllama) { $skip += 'ollama' } elseif ($NoModels) { $skip += 'models' }
$doctorArgs = @((Join-Path $Root 'tools\doctor.py'))
if ($skip.Count -gt 0) { $doctorArgs += @('--skip', ($skip -join ',')) }
$docExe = $VenvPy
$docPre = @()
if (-not (Test-Path $VenvPy)) {
    if ($script:Python) {
        $docExe = $script:Python[0]
        if ($script:Python.Count -gt 1) { $docPre = $script:Python[1..($script:Python.Count - 1)] }
    } else {
        Bad 'No Python to run the doctor with. Install Python 3.13 (winget install Python.Python.3.13), then run setup again.'
        exit 1
    }
}
& $docExe @($docPre + $doctorArgs)
$rc = $LASTEXITCODE
Write-Log "---- setup.ps1 end: doctor exit $rc (winget present: $haveWinget)"
if ($rc -eq 0) {
    Write-Host ''
    Write-Host 'Next: start Lab M1. Run lab commands with the shared Python, for example:'
    Write-Host '  .venv\Scripts\python.exe labs\m01\llm_lab.py'
    Write-Host 'or activate it once per window: .venv\Scripts\Activate.ps1 (docs/SETUP.md explains the execution policy prompt).'
} else {
    Write-Host ''
    Write-Host 'Run setup.ps1 again after fixing the items above (it skips what is already done).'
}
exit $rc
