# Suggested update for lesson 0.6 (lab setup)

For the owner. The lesson lives in the private course-content repo
(`modules/m00-start-here/0.6-lab-setup.md`); nothing there was changed. Below: what to change and why, then
replacement text you can paste. All of it follows the lesson standard (7 steps, professional headings for
students) and passes the house-voice check.

## Why update it

1. **The labs repo now has a one-time setup script** (`setup.sh` / `setup.ps1`) that does Steps 1 to 4 of the
   lesson and the checks in Step 5. The lesson should send students to it first and keep the manual steps as
   the fallback and as the explanation of what the script does.
2. **Python 3.10 is no longer enough.** The lesson says "Python 3.10 or newer", but labs M5, M7 and M10 onwards
   need 3.11 (their READMEs say so). Ubuntu 22.04's `python3` is 3.10, so a student following the lesson today
   hits a `SyntaxError` in Module 5. The script installs 3.11+ and the doctor checks it.
3. **Docker is not used by the local labs yet.** The lesson says "later labs run vulnerable apps inside
   containers". As of M14 no lab's laptop steps need Docker (AZ14's cloud build uses Azure's registry and says
   "No Docker needed"). Either keep Docker for the labs you plan (the script and doctor check it) or say
   "you'll need it from Module X". Your call: the text below keeps Docker and does not promise which module.
4. **M9 actually needs Python 3.12.** Lab M9 pins `numpy==2.5.4`, and numpy 2.5.4 requires Python 3.12 or
   newer (its PyPI metadata), while the M9 README says "All install on Python 3.11-3.13". On Ubuntu 22.04 and
   Debian 12 (newest Python: 3.11) `make setup` in M9 fails. Two fixes, pick one: pin a numpy that supports
   3.11 (the 2.3 or 2.4 series) and re-run the M9 tests, or change the M9 README to "Python 3.12-3.13". Until
   then the doctor warns students on 3.11 before they reach M9.
5. **Disk:** the lesson says about 10 GB; with two models, Docker images and the M4 packages, 15 GB free is a
   safer figure, and the script warns below it.
6. **Second model.** The script also pulls `embeddinggemma` (about 622 MB) for the optional real-embedding step
   in the RAG lab (M6 Step 7). If you'd rather not, remove it from `MODELS` in `setup.sh`, `setup.ps1` and
   `tools/doctor.py`.

## Replacement text

Insert this as the first part of **"Fix it + spot it"**, before "Step 1: Install Docker", and rename the existing
Steps 1 to 4 heading block to "### Doing it by hand (or seeing what the script did)".

---

### The fast way: one setup script

The labs repo has a setup script that checks your computer, installs what is missing, starts Ollama safely and
finishes with a health check. It asks before every install, so you stay in control.

1. Get the labs. Mac / Linux: open Terminal. Windows: open PowerShell.

   ```bash
   git clone https://github.com/thesecguyofficial/ai-security-course-labs.git
   cd ai-security-course-labs
   ```

   No git yet? On the GitHub page, click **Code → Download ZIP**, unzip it, and open a terminal in that folder.

2. Before you run it, check the fingerprint. This is a security course, so we don't pipe scripts from the
   internet straight into a shell. Compare the output with the hashes in the repo's latest release notes:

   ```bash
   shasum -a 256 setup.sh            # Mac (Linux: sha256sum setup.sh)
   ```

   ```powershell
   Get-FileHash setup.ps1 -Algorithm SHA256        # Windows
   ```

   Then open the script in any text editor and skim it. You don't need to understand every line. Look for
   what it downloads and from where.

3. Run it:

   ```bash
   ./setup.sh                                          # Mac, Linux, WSL
   ```

   ```powershell
   powershell -ExecutionPolicy Bypass -File setup.ps1  # Windows
   ```

   It installs (after asking) git, Python 3.11 or newer, Docker, Ollama, and downloads `gemma3:1b` (about
   806 MB) and `embeddinggemma` (about 622 MB). On Windows it may need to turn on WSL 2 and ask you to restart:
   restart, then run the same command again and it carries on where it stopped.

4. Read the last screen. The **doctor** prints a tick or a cross for each item, and every cross comes with the
   exact next step. Run it again any time:

   ```bash
   make doctor                   # Windows: py tools\doctor.py
   ```

   You want a tick on **"Ollama listens on 127.0.0.1 only"**. The doctor checks it for you, and Step 5 below
   shows how to check it by hand.

Stuck? `docs/SETUP.md` in the labs repo covers the usual problems: Docker not running, the WSL restart, work
laptops behind a proxy, Apple silicon, and low memory.

---

## Smaller edits in the same lesson

- **"What your computer needs"**: change "Free disk space: about 10 GB" to "Free disk space: about 15 GB".
- **Step 2: Install Python**: change "You need Python 3.10 or newer" to "You need Python 3.11 or newer
  (Python 3.13 is what every lab is tested on)". In the Linux line, add: "On Ubuntu 22.04, `python3` is 3.10:
  install `python3.11 python3.11-venv` as well."
- **Step 1, Linux**: the script installs the distribution's `docker.io` package with apt instead of running
  `get.docker.com`. Both are fine for the labs. If you keep the `get.docker.com` steps for the manual path, add
  one line: "The setup script uses your distribution's `docker.io` package instead, which updates with your
  normal system updates."
- **Recap, "What you do"**: add "run the setup script's doctor after you install anything new".
- **OWNER-NOTE**: the slot is still open. A real setup problem you hit yourself (Docker, WSL, Python versions)
  fits well next to the troubleshooting pointer.
