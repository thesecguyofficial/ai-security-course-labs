#!/usr/bin/env bash
# setup.sh: one-time lab setup for AI Security Engineer (The Sec Guy).
# macOS (Apple silicon and Intel), Ubuntu / Debian Linux, and Linux inside WSL on Windows.
#
# What it does, in order (it asks before every install, and you can say no):
#   1. Looks at this computer: OS, CPU, memory, free disk, signs of a work-managed laptop.
#   2. Installs what is missing: git, Python 3.11+, Docker, Ollama. It uses the normal installer for your
#      system: Homebrew on macOS (installed only if you agree), apt on Ubuntu/Debian, Ollama's official
#      script on Linux (downloaded to a file first so you can read it).
#   3. Starts Ollama on 127.0.0.1 (never 0.0.0.0), downloads the two lab models (sizes shown first).
#   4. Creates ONE shared Python virtual environment, .venv, at the repo root.
#   5. Runs tools/doctor.py, which prints a tick or a cross per item with the exact next step.
#
# Safe to run again: it skips whatever is already done. No telemetry: the only downloads are the
# installers and packages you agree to, and the models. Everything it does is written to setup.log.
# It uses sudo only for package installs and to start the services they install (Docker, Ollama).
#
# Usage:
#   ./setup.sh               interactive (recommended the first time)
#   ./setup.sh --check       look only: report what is missing, change nothing
#   ./setup.sh --yes         answer yes to every install question (for CI or a second machine)
#   ./setup.sh --uninstall   remove what this script made in the repo (.venv, lab models); see docs/SETUP.md
# Options: --no-docker  --no-ollama  --no-models  --docker=desktop|colima|engine  --help
# Help and common errors: docs/SETUP.md

set -u
set -o pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
LOG="$ROOT/setup.log"
VENV="$ROOT/.venv"
REQS="$ROOT/requirements-common.txt"
OLLAMA_API="http://127.0.0.1:11434"
MODELS=("gemma3:1b" "embeddinggemma")
MODEL_SIZES=("about 806 MB" "about 622 MB")
MODELS_TOTAL="about 1.4 GB"
MIN_RAM_GB=8
MIN_DISK_GB=15

ASSUME_YES=0
CHECK_ONLY=0
UNINSTALL=0
NO_DOCKER=0
NO_OLLAMA=0
NO_MODELS=0
DOCKER_CHOICE=""
APT_UPDATED=0
TMPDIR_SETUP=""
SUDO=""
OS=""
DISTRO=""
IS_WSL=0
PY=""

usage() {
  sed -n '2,/^# Help and common errors/p' "$0" | sed 's/^# \{0,1\}//'
}

for arg in "$@"; do
  case "$arg" in
    -y|--yes) ASSUME_YES=1 ;;
    --check) CHECK_ONLY=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --no-docker) NO_DOCKER=1 ;;
    --no-ollama) NO_OLLAMA=1; NO_MODELS=1 ;;
    --no-models) NO_MODELS=1 ;;
    --docker=desktop|--docker=colima|--docker=engine) DOCKER_CHOICE="${arg#--docker=}" ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown option: %s (try --help)\n' "$arg" >&2; exit 2 ;;
  esac
done

# ------------------------------------------------------------------ output, log, questions

if [ -t 1 ]; then
  C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_B=$'\033[1m'; C_0=$'\033[0m'
else
  C_OK=""; C_WARN=""; C_ERR=""; C_B=""; C_0=""
fi

log_only() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >>"$LOG"; }
say()      { printf '%s\n' "$*"; log_only "$*"; }
step()     { printf '\n%s== %s%s\n' "$C_B" "$*" "$C_0"; log_only "== $*"; }
ok()       { printf '  %s\xe2\x9c\x93%s %s\n' "$C_OK" "$C_0" "$*"; log_only "ok: $*"; }
warn()     { printf '  %s!%s %s\n' "$C_WARN" "$C_0" "$*"; log_only "warn: $*"; }
bad()      { printf '  %s\xe2\x9c\x97%s %s\n' "$C_ERR" "$C_0" "$*"; log_only "missing: $*"; }
have()     { command -v "$1" >/dev/null 2>&1; }

# Run a command, show it, copy its output to setup.log. Returns the command's exit code.
run() {
  printf '  %s$ %s%s\n' "$C_B" "$*" "$C_0"
  log_only "run: $*"
  "$@" 2>&1 | tee -a "$LOG"
  local rc=${PIPESTATUS[0]}
  [ "$rc" -eq 0 ] || log_only "exit code $rc: $*"
  return "$rc"
}

# Same, with sudo (or directly when already root). Says why before the password prompt.
run_sudo() {
  if [ -n "$SUDO" ]; then
    printf '  (sudo may ask for your computer password for the next command)\n'
  fi
  run $SUDO "$@"
}

# True when a terminal can really be opened for questions (the file can exist without one, e.g. in CI).
tty_ok() { { : </dev/tty; } 2>/dev/null; }

# ask "Question" [Y|N]: returns 0 for yes. --yes answers the default-yes questions with yes;
# questions whose safe answer is no (default N) stay no under --yes.
ask() {
  local q="$1" def="${2:-Y}" reply hint="[Y/n]"
  [ "$def" = "N" ] && hint="[y/N]"
  if [ "$ASSUME_YES" -eq 1 ]; then
    if [ "$def" = "Y" ]; then say "  $q $hint y (--yes)"; return 0; fi
    say "  $q $hint n (--yes keeps the safe answer here)"; return 1
  fi
  if ! tty_ok; then
    say "  $q $hint no terminal to ask in, so: no (run with --yes to accept)"; return 1
  fi
  printf '  %s %s ' "$q" "$hint"
  if ! read -r reply </dev/tty; then printf '\n'; log_only "ask: $q -> no answer"; return 1; fi
  log_only "ask: $q -> ${reply:-<default $def>}"
  case "$reply" in
    [Yy]|[Yy][Ee][Ss]) return 0 ;;
    [Nn]|[Nn][Oo]) return 1 ;;
    "") [ "$def" = "Y" ] ;;
    *) return 1 ;;
  esac
}

# shellcheck disable=SC2329  # called by the EXIT trap
cleanup() { if [ -n "$TMPDIR_SETUP" ]; then rm -rf "$TMPDIR_SETUP"; fi; }
trap cleanup EXIT

sha256_of() {
  if have sha256sum; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# Download an official install script to a file, show its fingerprint, offer to read it, then run it.
# Never "curl | sh": in a security course we read what we run.
fetch_and_run_script() {
  local name="$1" url="$2" runner="$3" file
  shift 3
  [ -n "$TMPDIR_SETUP" ] || TMPDIR_SETUP="$(mktemp -d)"
  file="$TMPDIR_SETUP/$name"
  run curl -fsSL --proto '=https' --tlsv1.2 -o "$file" "$url" || { bad "could not download $url"; return 1; }
  say "  Downloaded $url"
  say "  to $file ($(wc -l <"$file" | tr -d ' ') lines, SHA-256 $(sha256_of "$file"))"
  if [ "$ASSUME_YES" -eq 0 ] && ask "Read the script before it runs? (q quits the viewer)" Y; then
    "${PAGER:-less}" "$file" </dev/tty >/dev/tty || true
  fi
  ask "Run $name now?" Y || return 1
  run "$runner" "$file" "$@"
}

# ------------------------------------------------------------------ 1. this computer

detect_system() {
  step "1. This computer"
  local arch ram_kb ram_gb free_kb free_gb macver
  OS="$(uname -s)"
  arch="$(uname -m)"
  case "$OS" in
    Darwin)
      macver="$(sw_vers -productVersion 2>/dev/null || echo '?')"
      if [ "$arch" = "arm64" ]; then ok "macOS $macver, Apple silicon ($arch)"
      elif [ "$(sysctl -n sysctl.proc_translated 2>/dev/null)" = "1" ]; then
        warn "macOS $macver, Apple silicon, but this terminal runs under Rosetta (Intel mode)."
        warn "Open Terminal normally (Get Info: untick 'Open using Rosetta') and run setup again, or tools install for the wrong chip."
      else ok "macOS $macver, Intel ($arch)"; fi
      ram_gb=$(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1024 / 1024 / 1024 ))
      ;;
    Linux)
      if grep -qi microsoft /proc/version 2>/dev/null; then IS_WSL=1; fi
      if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        DISTRO="$(. /etc/os-release; printf '%s %s' "${ID:-linux}" "${ID_LIKE:-}")"
        ok "$(. /etc/os-release; printf '%s' "${PRETTY_NAME:-Linux}") ($arch)$( [ "$IS_WSL" -eq 1 ] && printf ', inside WSL')"
      else
        ok "Linux ($arch)"
      fi
      ram_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
      ram_gb=$(( (ram_kb + 524288) / 1024 / 1024 ))
      ;;
    *)
      bad "$OS is not supported by setup.sh. Windows: use setup.ps1 (see README Quick start)."
      exit 2 ;;
  esac
  if [ "$ram_gb" -lt "$MIN_RAM_GB" ]; then
    warn "Memory: ${ram_gb} GB. Below ${MIN_RAM_GB} GB the labs still run (most use a stand-in model), but close other apps when a real model runs."
  else
    ok "Memory: ${ram_gb} GB"
  fi
  free_kb="$(df -Pk "$ROOT" | awk 'NR==2 {print $4}')"
  free_gb=$(( free_kb / 1024 / 1024 ))
  if [ "$free_gb" -lt "$MIN_DISK_GB" ]; then
    warn "Free disk: ${free_gb} GB. ${MIN_DISK_GB} GB is comfortable (models ${MODELS_TOTAL}, Docker images, lab packages)."
  else
    ok "Free disk: ${free_gb} GB"
  fi

  # Work laptop hints. We never log proxy values: they can contain a user name and password.
  local hints=""
  if [ -n "${HTTPS_PROXY:-}${https_proxy:-}${HTTP_PROXY:-}${http_proxy:-}" ]; then hints="$hints, a proxy is set"; fi
  if [ "$OS" = "Darwin" ] && profiles status -type enrollment 2>/dev/null | grep -qi 'MDM enrollment: Yes'; then
    hints="$hints, this Mac is enrolled in device management (MDM)"
  fi
  if [ -d /opt/CrowdStrike ] || [ -d /opt/microsoft/mdatp ] || [ -d /Library/CS ] || [ -d "/Applications/Falcon.app" ]; then
    hints="$hints, a company security agent is installed"
  fi
  if [ -n "$hints" ]; then
    warn "Looks like a work-managed computer: ${hints#, }."
    warn "Installs may be blocked, and Docker Desktop may need a paid licence at a large company. Ask IT first. docs/SETUP.md, 'Work laptops'."
  fi

  if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
    [ "$CHECK_ONLY" -eq 1 ] || warn "Running as root. On your own computer, run as your normal user: the script asks for sudo only when needed."
  else
    SUDO="sudo"
  fi
}

is_apt_system() {
  [ "$OS" = "Linux" ] && have apt-get && case " $DISTRO " in *debian*|*ubuntu*) true ;; *) false ;; esac
}

apt_install() {
  if [ "$APT_UPDATED" -eq 0 ]; then run_sudo apt-get update || return 1; APT_UPDATED=1; fi
  run_sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
}

has_systemd() { [ "$(ps -p 1 -o comm= 2>/dev/null)" = "systemd" ]; }

# ------------------------------------------------------------------ 2. package manager (macOS: Homebrew)

brew_shellenv() {
  local b
  for b in /opt/homebrew/bin/brew /usr/local/bin/brew; do
    if [ -x "$b" ]; then eval "$("$b" shellenv)"; return 0; fi
  done
  return 1
}

ensure_brew() {
  [ "$OS" = "Darwin" ] || return 0
  have brew || brew_shellenv
  if have brew; then ok "Homebrew $(brew --version 2>/dev/null | head -1 | awk '{print $2}')"; return 0; fi
  bad "Homebrew (macOS package manager, brew.sh) is not installed. setup.sh uses it to install the other tools."
  [ "$CHECK_ONLY" -eq 1 ] && return 1
  ask "Install Homebrew? It is free and open source, and asks for your Mac password once" Y || return 1
  if [ "$ASSUME_YES" -eq 1 ]; then export NONINTERACTIVE=1; fi
  fetch_and_run_script "homebrew-install.sh" "https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh" /bin/bash || return 1
  brew_shellenv || { bad "Homebrew installed but brew is not on PATH. Open a new terminal and run setup again."; return 1; }
  local line profile="$HOME/.zprofile"
  line="eval \"\$($(command -v brew) shellenv)\""
  if ! grep -qsF "$line" "$profile"; then
    if ask "Add Homebrew to your PATH for new terminals (one line in ~/.zprofile)?" Y; then
      printf '\n%s\n' "$line" >>"$profile"; ok "added to $profile"
    fi
  fi
  ok "Homebrew installed"
}

# ------------------------------------------------------------------ 3. git, make, curl

ensure_basics() {
  step "2. Basic tools: git, make, curl"
  local missing=()
  for t in git make curl; do
    if have "$t"; then ok "$t"; else bad "$t"; missing+=("$t"); fi
  done
  [ "${#missing[@]}" -eq 0 ] && return 0
  [ "$CHECK_ONLY" -eq 1 ] && return 1
  if [ "$OS" = "Darwin" ]; then
    if ! xcode-select -p >/dev/null 2>&1; then
      warn "Apple's Command Line Tools give you git and make. A window will ask you to install them."
      if ask "Open the Command Line Tools installer now?" Y; then
        run xcode-select --install || true
        say "  When that install finishes, run ./setup.sh again."
        return 1
      fi
    fi
    ensure_brew && ask "Install ${missing[*]} with Homebrew?" Y && run brew install "${missing[@]}"
  elif is_apt_system; then
    ask "Install ${missing[*]} with apt?" Y && apt_install "${missing[@]}"
  else
    warn "Install ${missing[*]} with your system's package manager, then run setup again."
    return 1
  fi
}

# ------------------------------------------------------------------ 4. Python 3.11+

py_version() { "$1" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null; }

# Picks the best Python for the labs: 3.13 (every lab is tested on it), then 3.12, 3.11, then newer ones.
find_python() {
  local c v best="" best_score=0 score cands=(python3.13 python3.12 python3.11 python3 python3.14 python3.15)
  if [ "$OS" = "Darwin" ] && have brew; then
    cands+=("$(brew --prefix 2>/dev/null)/bin/python3.13")
  fi
  for c in "${cands[@]}"; do
    have "$c" || [ -x "$c" ] || continue
    v="$(py_version "$c")" || continue
    case "$v" in
      3.13) score=50 ;; 3.12) score=40 ;; 3.11) score=30 ;;
      3.1[4-9]) score=20 ;; *) score=0 ;;
    esac
    if [ "$score" -gt "$best_score" ]; then best="$c"; best_score=$score; fi
  done
  [ -n "$best" ] && PY="$(command -v "$best" 2>/dev/null || printf '%s' "$best")"
  [ -n "$best" ]
}

python_can_make_venv() {
  "$1" -c 'import venv, ensurepip' >/dev/null 2>&1
}

ensure_python() {
  step "3. Python 3.11 or newer"
  if find_python; then
    ok "Python $(py_version "$PY") at $PY"
    if ! python_can_make_venv "$PY"; then
      bad "Python $(py_version "$PY") cannot create virtual environments (the venv package is missing)"
      [ "$CHECK_ONLY" -eq 1 ] && return 1
      if is_apt_system && ask "Install python$(py_version "$PY")-venv with apt?" Y; then
        apt_install "python$(py_version "$PY")-venv" || return 1
      else
        return 1
      fi
    fi
    return 0
  fi
  local found=""
  have python3 && found=" (found $(py_version python3), the labs need 3.11+)"
  bad "Python 3.11 or newer$found"
  [ "$CHECK_ONLY" -eq 1 ] && return 1
  if [ "$OS" = "Darwin" ]; then
    ensure_brew && ask "Install Python 3.13 with Homebrew?" Y && run brew install python@3.13 || return 1
  elif is_apt_system; then
    local cand
    cand="$(apt-cache policy python3 2>/dev/null | awk '/Candidate:/ {print $2}')"
    case "$cand" in
      3.1[1-9]*) ask "Install Python $cand with apt?" Y && apt_install python3 python3-venv python3-pip || return 1 ;;
      *)
        # Ubuntu 22.04 ships Python 3.10 as python3, and Python 3.11 as a separate package.
        if apt-cache show python3.11 >/dev/null 2>&1; then
          ask "Install Python 3.11 with apt (next to your system's $cand, which stays as it is)?" Y \
            && apt_install python3.11 python3.11-venv || return 1
        else
          warn "Your system has no Python 3.11+ package. Upgrade the OS (Ubuntu 24.04 / Debian 12) or see docs/SETUP.md."
          return 1
        fi ;;
    esac
  else
    warn "Install Python 3.11+ with your package manager (or python.org), then run setup again."
    return 1
  fi
  find_python && ok "Python $(py_version "$PY") at $PY"
}

# ------------------------------------------------------------------ 5. Docker

docker_running() { docker info >/dev/null 2>&1; }

docker_licence_note() {
  say "  Docker Desktop is free for personal use, education, non-commercial open source and small businesses"
  say "  (fewer than 250 employees AND under \$10 million a year). Larger companies need a paid plan."
  say "  Terms change: check https://docs.docker.com/subscription/desktop-license/ before you accept."
}

ensure_docker() {
  step "4. Docker (runs lab apps in throwaway containers)"
  if [ "$NO_DOCKER" -eq 1 ]; then warn "skipped (--no-docker)"; return 0; fi
  if have docker; then
    ok "Docker installed ($(docker --version 2>/dev/null | head -1))"
    start_docker
    return 0
  fi
  bad "Docker"
  [ "$CHECK_ONLY" -eq 1 ] && return 1

  if [ "$OS" = "Darwin" ]; then
    local choice="$DOCKER_CHOICE"
    if [ -z "$choice" ]; then
      docker_licence_note
      say "  Free alternative: Colima (open source, MIT licence, command line only, no licence terms to check)."
      if [ "$ASSUME_YES" -eq 1 ]; then choice="desktop"
      elif tty_ok; then
        printf '  Install [d]ocker Desktop, [c]olima, or [s]kip? [d/c/s] '
        read -r choice </dev/tty || choice="s"
        case "$choice" in [Dd]*) choice="desktop" ;; [Cc]*) choice="colima" ;; *) choice="skip" ;; esac
      else choice="skip"; fi
      log_only "docker choice: $choice"
    fi
    case "$choice" in
      desktop)
        ensure_brew || return 1
        run brew install --cask docker-desktop || return 1
        say "  Opening Docker Desktop: accept the agreement in its window (first launch only)."
        open -a Docker || true ;;
      colima)
        ensure_brew || return 1
        run brew install colima docker || return 1 ;;
      *) warn "Docker skipped. Run setup again when you want it."; return 1 ;;
    esac
  elif [ "$IS_WSL" -eq 1 ]; then
    say "  In WSL the usual way is Docker Desktop on Windows with WSL integration turned on"
    say "  (Docker Desktop, Settings, Resources, WSL integration, tick this distro). Then 'docker' works here."
    docker_licence_note
    if [ "$DOCKER_CHOICE" = "engine" ] || ask "Install Docker Engine inside this WSL distro instead?" N; then
      install_docker_engine_apt || return 1
    else
      return 1
    fi
  elif is_apt_system; then
    install_docker_engine_apt || return 1
  else
    warn "Install Docker Engine for your distro: https://docs.docker.com/engine/install/ , then run setup again."
    return 1
  fi
  start_docker
}

install_docker_engine_apt() {
  say "  Docker Engine from your distro's own package (docker.io): free, updated with your normal system updates."
  ask "Install Docker Engine with apt?" Y || return 1
  apt_install docker.io || return 1
  if has_systemd; then run_sudo systemctl enable --now docker || true; fi
  if [ "$(id -u)" -ne 0 ] && ! id -nG "$USER" | tr ' ' '\n' | grep -qx docker; then
    say "  Without the docker group you run Docker as 'sudo docker ...'. With it, no sudo, but Docker's own docs"
    say "  warn the group 'grants root-level privileges to the user'. Fine on your own laptop, not on a shared one."
    if ask "Add $USER to the docker group?" N; then
      run_sudo usermod -aG docker "$USER" && warn "Log out and back in (or run: newgrp docker) before Docker works without sudo."
    fi
  fi
}

start_docker() {
  if docker_running; then ok "Docker engine running"; return 0; fi
  [ "$CHECK_ONLY" -eq 1 ] && { bad "Docker engine is not running (or your user may not use it)"; return 1; }
  if [ "$OS" = "Darwin" ]; then
    if [ -d /Applications/Docker.app ]; then say "  Starting Docker Desktop..."; open -a Docker || true
    elif have colima; then run colima start || true; fi
  elif [ "$IS_WSL" -eq 0 ] && has_systemd; then
    if $SUDO docker info >/dev/null 2>&1; then
      warn "Docker runs, but only with sudo for your user (see the docker group question above)."
      return 0
    fi
    run_sudo systemctl start docker || true
  fi
  local i
  for i in $(seq 1 60); do
    docker_running && { ok "Docker engine running"; return 0; }
    [ $((i % 10)) -eq 0 ] && say "  waiting for the Docker engine ($((i * 2)) s)..."
    sleep 2
  done
  warn "Docker is installed but the engine is not answering yet. Start Docker Desktop (or colima start / sudo systemctl start docker); doctor will check again."
  return 1
}

# ------------------------------------------------------------------ 6. Ollama + models

ollama_up() { curl -fsS --max-time 2 "$OLLAMA_API/api/version" >/dev/null 2>&1; }

check_ollama_host_env() {
  case "${OLLAMA_HOST:-}" in
    ""|127.0.0.1*|localhost*|http://127.0.0.1*|http://localhost*) return 0 ;;
    *) warn "OLLAMA_HOST is set in this terminal. Ollama has no login: on 0.0.0.0 anyone on your network can use it."
       warn "Remove that setting from your shell profile (lesson 0.6, Step 5). setup.sh starts Ollama without it." ;;
  esac
}

ensure_ollama() {
  step "5. Ollama (runs AI models on this computer)"
  if [ "$NO_OLLAMA" -eq 1 ]; then warn "skipped (--no-ollama)"; return 0; fi
  check_ollama_host_env
  if have ollama; then
    ok "Ollama installed ($(ollama --version 2>/dev/null | tail -1))"
  else
    bad "Ollama"
    [ "$CHECK_ONLY" -eq 1 ] && return 1
    if [ "$OS" = "Darwin" ]; then
      ensure_brew || return 1
      local major
      major="$(sw_vers -productVersion 2>/dev/null | cut -d. -f1)"
      if [ "${major:-0}" -ge 14 ]; then
        ask "Install the Ollama app with Homebrew (cask ollama-app)?" Y && run brew install --cask ollama-app || return 1
      else
        say "  The Ollama app needs macOS 14 or newer; Homebrew's command-line build works on older versions."
        ask "Install Ollama (command line) with Homebrew?" Y && run brew install ollama || return 1
      fi
    else
      say "  Ollama's official Linux installer is a script. It uses sudo to put ollama in /usr/local and,"
      say "  with systemd, adds an 'ollama' service that listens on 127.0.0.1 only."
      ask "Download Ollama's installer from ollama.com?" Y || return 1
      if ! have zstd; then
        # Current Ollama releases for Linux are .tar.zst archives: the installer stops without zstd.
        if is_apt_system; then apt_install zstd || return 1
        else warn "Install zstd with your package manager first (Ollama's installer needs it)."; return 1; fi
      fi
      fetch_and_run_script "ollama-install.sh" "https://ollama.com/install.sh" sh || return 1
    fi
    have ollama || { bad "ollama is still not on PATH. Open a new terminal and run setup again."; return 1; }
  fi
  start_ollama
}

start_ollama() {
  if ollama_up; then ok "Ollama answering on $OLLAMA_API"; return 0; fi
  [ "$CHECK_ONLY" -eq 1 ] && { bad "Ollama is not running"; return 1; }
  say "  Starting Ollama on 127.0.0.1:11434..."
  local started=0
  if [ "$OS" = "Darwin" ] && [ -d /Applications/Ollama.app ]; then
    open -a Ollama && started=1
  elif [ "$OS" = "Linux" ] && has_systemd && systemctl cat ollama >/dev/null 2>&1; then
    run_sudo systemctl start ollama && started=1
  fi
  if [ "$started" -eq 1 ] && wait_for_ollama 15; then return 0; fi
  # No app and no service (WSL without systemd, CI, Homebrew command-line build), or it did not answer:
  # run it in the background. env -u OLLAMA_HOST makes sure it uses the safe default address 127.0.0.1.
  say "  (running 'ollama serve' in the background; its output goes to .ollama-serve.log)"
  nohup env -u OLLAMA_HOST ollama serve >>"$ROOT/.ollama-serve.log" 2>&1 &
  wait_for_ollama 30 && return 0
  bad "Ollama did not start. See .ollama-serve.log or docs/SETUP.md."
  return 1
}

# wait_for_ollama N: poll every 2 s, N times.
wait_for_ollama() {
  local i
  for i in $(seq 1 "$1"); do
    ollama_up && { ok "Ollama answering on $OLLAMA_API"; return 0; }
    sleep 2
  done
  return 1
}

model_present() {
  curl -fsS --max-time 5 "$OLLAMA_API/api/tags" 2>/dev/null | grep -Eq "\"name\":\"$1(:latest)?\""
}

ensure_models() {
  step "6. Lab models"
  if [ "$NO_MODELS" -eq 1 ]; then warn "skipped (--no-models)"; return 0; fi
  if ! ollama_up; then bad "Ollama is not running, so models cannot be checked"; return 1; fi
  local i missing=() sizes=()
  for i in "${!MODELS[@]}"; do
    if model_present "${MODELS[$i]}"; then ok "${MODELS[$i]}"
    else bad "${MODELS[$i]} (${MODEL_SIZES[$i]})"; missing+=("${MODELS[$i]}"); sizes+=("${MODEL_SIZES[$i]}"); fi
  done
  [ "${#missing[@]}" -eq 0 ] && return 0
  [ "$CHECK_ONLY" -eq 1 ] && return 1
  say "  gemma3:1b is the course's small chat model; embeddinggemma turns text into vectors (RAG labs)."
  local what="${MODELS_TOTAL} for both"
  [ "${#missing[@]}" -eq 1 ] && what="${sizes[0]}"
  ask "Download ${missing[*]} (${what})?" Y || return 1
  for i in "${missing[@]}"; do
    run env -u OLLAMA_HOST ollama pull "$i" || { bad "could not download $i (check your internet or proxy)"; return 1; }
  done
}

# ------------------------------------------------------------------ 7. shared virtual environment

ensure_venv() {
  step "7. Shared Python environment (.venv)"
  if [ -x "$VENV/bin/python" ]; then
    local v
    v="$(py_version "$VENV/bin/python")"
    case "$v" in
      3.1[1-9]) if "$VENV/bin/python" -m pip --version >/dev/null 2>&1; then ok ".venv exists (Python $v)"; install_common; return $?; fi ;;
    esac
    bad ".venv exists but is broken or too old (Python ${v:-unknown})"
    [ "$CHECK_ONLY" -eq 1 ] && return 1
    ask "Delete .venv and make it again?" Y || return 1
    run rm -rf "$VENV"
  else
    bad ".venv not created yet"
    [ "$CHECK_ONLY" -eq 1 ] && return 1
  fi
  [ -n "$PY" ] || find_python || { bad "no Python 3.11+ to build .venv with"; return 1; }
  run "$PY" -m venv "$VENV" || return 1
  ok ".venv created with Python $(py_version "$VENV/bin/python")"
  install_common
}

install_common() {
  # Only install when the file lists a package (the core labs use the standard library only).
  if [ -f "$REQS" ] && grep -Eq '^[[:space:]]*[A-Za-z0-9]' "$REQS"; then
    [ "$CHECK_ONLY" -eq 1 ] && return 0
    run "$VENV/bin/python" -m pip install --disable-pip-version-check -q -r "$REQS" || return 1
    ok "common packages installed"
  fi
}

# ------------------------------------------------------------------ uninstall

do_uninstall() {
  step "Remove what setup.sh made"
  if [ -d "$VENV" ] && ask "Delete the shared .venv folder?" Y; then run rm -rf "$VENV"; fi
  local d
  for d in "$ROOT"/labs/*/.venv; do
    [ -d "$d" ] || continue
    if ask "Delete ${d#"$ROOT"/} (made by that lab's make setup)?" Y; then run rm -rf "$d"; fi
  done
  if have ollama && ollama_up; then
    local m
    for m in "${MODELS[@]}"; do
      if model_present "$m" && ask "Delete the model $m?" Y; then run ollama rm "$m"; fi
    done
  else
    say "  Ollama is not running: to delete the models later, run: ollama rm gemma3:1b embeddinggemma"
  fi
  rm -f "$ROOT/.ollama-serve.log"
  say ""
  say "Left installed on purpose (you may use them for other things): Docker, Ollama, Python, git, Homebrew."
  say "To remove those too, see docs/SETUP.md, 'Uninstall'. setup.log stays until you delete it."
}

# ------------------------------------------------------------------ main

main() {
  log_only "---- setup.sh start: args=[$*] check=$CHECK_ONLY yes=$ASSUME_YES"
  printf '%sAI Security Engineer: lab setup%s\n' "$C_B" "$C_0"
  if [ "$CHECK_ONLY" -eq 1 ]; then printf 'Check only: nothing is installed or changed.\n'; fi
  printf 'Log: %s\n' "$LOG"

  detect_system

  if [ "$UNINSTALL" -eq 1 ]; then do_uninstall; exit 0; fi

  if [ "$OS" = "Darwin" ]; then step "Package manager"; ensure_brew || true; fi
  ensure_basics || true
  ensure_python || true
  ensure_docker || true
  ensure_ollama || true
  ensure_models || true
  ensure_venv || true

  step "8. Doctor: final check"
  local doc_py="$VENV/bin/python" skip=""
  [ -x "$doc_py" ] || doc_py="${PY:-python3}"
  [ "$NO_DOCKER" -eq 1 ] && skip="docker"
  [ "$NO_OLLAMA" -eq 1 ] && skip="${skip:+$skip,}ollama"
  [ "$NO_MODELS" -eq 1 ] && [ "$NO_OLLAMA" -eq 0 ] && skip="${skip:+$skip,}models"
  "$doc_py" "$ROOT/tools/doctor.py" ${skip:+--skip "$skip"} 2>&1 | tee -a "$LOG"
  local rc=${PIPESTATUS[0]}
  log_only "---- setup.sh end: doctor exit $rc"
  if [ "$rc" -eq 0 ]; then
    printf '\nNext: activate the shared environment in each new terminal, then start Lab M1:\n'
    printf '  source .venv/bin/activate\n  cd labs/m01 && cat README.md\n'
    printf 'Labs M4, M6, M8 and M9 install their own packages with "make setup" inside their folder.\n'
  else
    printf '\nRun ./setup.sh again after fixing the items above (it skips what is already done).\n'
  fi
  exit "$rc"
}

main "$@"
