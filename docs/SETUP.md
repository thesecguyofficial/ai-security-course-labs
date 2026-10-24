# Lab setup: what the script does, options, and fixes

You run the setup script **once** per computer. It is safe to run again at any time: it skips everything that is
already done, so "run it again" is also the fix for most half-finished installs.

- macOS, Ubuntu/Debian Linux, WSL: `./setup.sh`
- Windows 10 22H2 / Windows 11: `powershell -ExecutionPolicy Bypass -File setup.ps1`
- Check only, change nothing: `./setup.sh --check` or `setup.ps1 -Check`
- Health check on its own: `make doctor`, or `python3 tools/doctor.py` (Windows: `py tools\doctor.py`)

## What it does, step by step

| Step | macOS | Ubuntu / Debian (and WSL) | Windows |
|---|---|---|---|
| 1. Look at this computer | OS, chip (Apple silicon or Intel), RAM, free disk, work-laptop hints | same | same, plus WSL 2 and virtualisation |
| 2. Package manager | Homebrew (installed only if you say yes) | apt (already there) | winget (already there on Windows 10/11) |
| 3. git, make, curl | Apple Command Line Tools or Homebrew | apt | winget `Git.Git` |
| 4. Python 3.11+ | `brew install python@3.13` | apt `python3` + `python3-venv` (Ubuntu 22.04: `python3.11`) | winget `Python.Python.3.13` |
| 5. Docker | Docker Desktop **or** Colima (you choose) | Docker Engine, apt package `docker.io` | Docker Desktop (needs WSL 2) |
| 6. Ollama | Homebrew cask `ollama-app` | Ollama's official install script, downloaded to a file first | winget `Ollama.Ollama` |
| 7. Models | `gemma3:1b` (about 806 MB) and `embeddinggemma` (about 622 MB) | same | same |
| 8. Shared `.venv` | one virtual environment at the repo root | same | same |
| 9. Doctor | `tools/doctor.py`: a tick or a cross per item, with the next step | same | same |

Every install is a question first (`Install X? [Y/n]`). Say `n` and the script carries on with the rest; the
doctor at the end tells you what is still missing.

**Why Python 3.11 and not 3.10?** Labs M5, M7 and M10 onwards use Python 3.11 features. The script picks 3.13
when you have it, because every lab is tested on 3.13. Two edges to know:

- **Python 3.11** (the newest on Ubuntu 22.04 and Debian 12) runs every lab, M9 included.
- **Python 3.14** works for most labs, but the pinned packages in M4 and M9 are tested up to 3.13.

**Why one shared `.venv`?** It gives every lab the same, right Python, even when your system's `python3` is
older. The core labs need nothing else. Labs M4, M6, M8 and M9 pin their own packages and install them in their
own folder with `make setup`, so one lab's versions can never break another lab.

## Options

| setup.sh | setup.ps1 | What it does |
|---|---|---|
| `--check` | `-Check` | Report only. Installs nothing, starts nothing, asks nothing |
| `--yes` | `-Yes` | Answers yes to every install question (for a second machine or CI). Questions whose safe answer is no stay no |
| `--no-docker` | `-NoDocker` | Skip Docker (the doctor skips it too) |
| `--no-ollama` | `-NoOllama` | Skip Ollama and the models |
| `--no-models` | `-NoModels` | Install Ollama but don't download the models yet |
| `--docker=desktop`, `--docker=colima`, `--docker=engine` | | Pick the Docker flavour without the question (`engine` = inside WSL) |
| `--uninstall` | `-Uninstall` | Remove what the script made in this repo (see Uninstall) |

Exit codes: `0` ready (warnings are fine), `1` something failed (the doctor says what), `2` wrong option or
unsupported system, `3` (Windows) restart needed, then run the same command again.

## Every day after setup

Mac / Linux / WSL: open a terminal in the repo folder and turn on the shared environment once per terminal:

```bash
source .venv/bin/activate      # your prompt now starts with (.venv)
cd labs/m01
```

Windows: either call the shared Python directly, for example `.venv\Scripts\python.exe labs\m01\llm_lab.py`, or
turn the environment on with `.venv\Scripts\Activate.ps1`. If PowerShell answers "running scripts is disabled",
allow your own local scripts once with `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` (it still blocks
unsigned scripts downloaded from the internet). The labs' `make` shortcuts are for Mac/Linux; each lab README
shows the plain `python` commands for Windows.

## What the script never does

- **No `curl | bash`.** Install scripts (Homebrew on macOS, Ollama on Linux) are downloaded to a file. You see
  the file's SHA-256 and can read it before you say yes.
- **No 0.0.0.0.** Ollama is started on its default address, `127.0.0.1:11434`. If your terminal has
  `OLLAMA_HOST` set, the script warns you and starts Ollama without it. The doctor fails if Ollama answers on any
  other address of your computer.
- **No telemetry.** Nothing about you or your computer is sent anywhere. The only downloads are the installers
  and packages you agree to (from Homebrew, apt, winget, ollama.com, PyPI) and the two models (from Ollama's
  library). The doctor talks only to `127.0.0.1` and lets Docker pull its tiny `hello-world` test image once.
- **sudo only for installs.** On Linux, `sudo` is used for `apt-get`, Ollama's installer and starting the Docker
  and Ollama services, and the command is printed before it runs. On Windows, only the installers that need
  administrator rights ask for them, through the normal Windows prompt.
- **No secrets in the log.** `setup.log` records each step, question and command. It notes that a proxy is set,
  never its value (proxy settings can hold a user name and password).

## Docker: which one, and the licence

- **Docker Desktop** (macOS, Windows) is free for personal use, education, non-commercial open source and small
  businesses (fewer than 250 employees **and** under $10 million a year in revenue). Larger companies need a paid
  plan. Docker changes its terms from time to time, so read the current
  [Docker Desktop licence](https://docs.docker.com/subscription/desktop-license/) before you accept it.
- **Colima** (macOS) is a free, open source (MIT) alternative that runs Docker from the command line. Choose
  `c` at the Docker question, or run `./setup.sh --docker=colima`. Start it after a reboot with `colima start`.
- **Docker Engine** (Linux) comes from your distribution's own `docker.io` package and updates with your system.
  Docker's own `docker-ce` packages work too
  ([docs.docker.com/engine/install](https://docs.docker.com/engine/install/)); the labs need nothing newer.
- **The docker group (Linux).** Without it you type `sudo docker ...`. With it you don't, but Docker's docs warn
  the group "grants root-level privileges to the user". The script asks, the default answer is no, and `--yes`
  keeps it no. On your own laptop, yes is a reasonable choice: `sudo usermod -aG docker $USER`, then log out and
  back in.

## Troubleshooting

The doctor's "next step" line is the first thing to try. These are the usual problems behind it.

### Docker is installed but "the engine is not answering"
- **macOS / Windows:** Docker Desktop must be running. Open it, wait until it shows **Engine running**, then run
  `make doctor` again. The first launch asks you to accept the agreement.
- **Colima:** run `colima start` (after every reboot).
- **Linux:** `sudo systemctl start docker`. "permission denied ... docker.sock" means the engine runs but your
  user may not use it: use `sudo docker`, or join the docker group (above) and log out and back in.
- **WSL:** install Docker Desktop on Windows, then Settings, Resources, WSL integration, and tick your distro.

### Windows: WSL 2, virtualisation and the restart
- The script turns WSL 2 on with `wsl --install --no-distribution`, which needs administrator rights and a
  restart. **Restart Windows, then run the same command again.** The script remembers it stopped there
  (`.setup-state.json`) and carries on.
- Still "WSL 2 is missing" after a restart: run `wsl --update` in an administrator PowerShell, restart again.
- "Virtualisation looks OFF": restart into your BIOS/UEFI settings (often F2, F10, Del or Esc at power-on) and turn
  on **Intel VT-x** / **Intel Virtualization Technology** or **AMD-V** / **SVM Mode**. On a work laptop this
  setting is often locked: ask IT.
- After Docker Desktop installs, sign out of Windows and back in once if Docker says your user is not allowed.

### Work laptops: proxy, TLS inspection, blocked installs
- **Ask first.** Company laptops often block installers, and Docker Desktop may need a company licence.
- **Proxy.** If your company uses one, it is usually already set as `HTTPS_PROXY`. `sudo` drops it for apt:
  ask IT for the apt proxy setting, or set `Acquire::https::Proxy` in `/etc/apt/apt.conf.d/`. Docker Desktop has
  its own proxy page (Settings, Resources, Proxies). Ollama uses `HTTPS_PROXY` when it downloads models.
- **TLS inspection** ("certificate verify failed", "x509: certificate signed by unknown authority"): the network
  replaces websites' certificates with the company's own. Ask IT for the company root certificate. Then point
  pip at it (`pip config set global.cert /path/to/company-root.pem`) and add it to Docker Desktop or the system
  trust store as IT describes. Never turn certificate checks off to "make it work".
- **The doctor says Docker cannot download `hello-world`:** Docker Hub (`registry-1.docker.io`) is blocked or
  needs the proxy settings above.

### Apple silicon Macs
- "Running under Rosetta (Intel mode)": your Terminal is set to open with Rosetta. Quit it, Finder,
  Applications, Utilities, Terminal, Get Info, untick **Open using Rosetta**, and run setup again. Otherwise
  Homebrew and Python install for the wrong chip.
- `brew: command not found` right after Homebrew installed: open a new terminal (the script adds Homebrew to
  `~/.zprofile` if you agreed), or run `eval "$(/opt/homebrew/bin/brew shellenv)"`.
- The Ollama app needs macOS 14 or newer. On older versions the script installs Ollama's command-line build and
  starts `ollama serve` in the background.

### Low memory (under 8 GB)
- The labs still run: most use a stand-in model written in plain Python.
- For the real-model steps, close browsers and other heavy apps first, and try the smaller `qwen3:0.6b`
  (lesson 0.6, Step 4).
- Docker Desktop reserves memory for its virtual machine. Lower it in Settings, Resources, or quit Docker
  Desktop when a lab doesn't need it.

### Python
- "Python 3.11 or newer" missing on **Ubuntu 22.04**: the script installs `python3.11` next to the system's 3.10
  (it doesn't replace it). Use the shared `.venv` and you get 3.11 automatically.
- M9's `make setup` says "No matching distribution found for numpy": that Python is older than 3.11. Run M9
  from the shared `.venv` (`. .venv/bin/activate` at the repo root first).
- "cannot create virtual environments": Debian and Ubuntu ship `venv` separately. The script installs
  `python3.X-venv`; by hand: `sudo apt install python3.12-venv` (your version number).
- A broken `.venv` (Python was upgraded or removed): delete the `.venv` folder and run setup again.

### Ollama
- "Ollama is not running": macOS, open Ollama from Applications; Windows, from the Start menu; Linux,
  `sudo systemctl start ollama`, or `ollama serve` in a second terminal where there is no systemd (WSL).
- **"Ollama listens on 127.0.0.1 only" failed:** something set `OLLAMA_HOST` (often a web UI's install guide).
  Remove it from your shell profile (`~/.zshrc`, `~/.bashrc`), the systemd unit
  (`sudo systemctl edit ollama`) or Windows' environment variables, then restart Ollama. Lesson 0.6, Step 5
  explains why this matters.
- A model download stops halfway: run `ollama pull gemma3:1b` again; it resumes.

### Other errors
- `./setup.sh: Permission denied`: the ZIP download lost the "executable" flag. Run `bash setup.sh`.
- `winget is not recognized`: install or update **App Installer** from the Microsoft Store.
- Low disk: `docker system prune` removes stopped containers and unused images (it asks first);
  `ollama rm <model>` removes a model.
- Anything else: open `setup.log`, find the last `exit code` line, and ask in
  [Discussions, Lab help](https://github.com/thesecguyofficial/ai-security-course-labs/discussions) with that line (check it holds nothing private first).

## Uninstall

`./setup.sh --uninstall` (Windows: `setup.ps1 -Uninstall`) asks, then removes:

- the shared `.venv` and any lab's own `.venv` (M4, M6, M8, M9);
- the two lab models (`ollama rm gemma3:1b embeddinggemma`).

It leaves Docker, Ollama, Python, git and Homebrew installed, because you may use them for other things. To
remove those too:

- **macOS:** `brew uninstall --cask docker-desktop ollama-app` (or `brew uninstall colima docker`), then
  `brew uninstall python@3.13` if nothing else uses it.
- **Ubuntu / Debian:** `sudo apt remove docker.io`. For Ollama, follow the uninstall steps in
  [Ollama's Linux docs](https://docs.ollama.com/linux) (stop the service, remove the binary and its user).
- **Windows:** Settings, Apps, Installed apps: Docker Desktop, Ollama, Python, Git.

`setup.log` stays until you delete it.

## For maintainers

- Tests: `make test-setup` (doctor unit tests, shellcheck, checksums, house voice). CI runs the full install on
  Ubuntu 24.04 and 22.04, macOS (no Docker on that runner) and Windows (no Docker Desktop on that runner):
  `.github/workflows/setup.yml`.
- After changing `setup.sh`, `setup.ps1` or `tools/doctor.py`, run `make checksums` and commit `SHA256SUMS`.

### Releasing

On every GitHub release, paste the current `SHA256SUMS` file into the release notes. Students compare the hash
of the `setup.sh` or `setup.ps1` they downloaded against it before they run anything, so the notes must match
the files in that release.
- `setup.ps1` must stay ASCII and run on Windows PowerShell 5.1 (no `&&`, `??` or `?.`): a test checks this.
