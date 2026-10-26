#!/usr/bin/env bash
# Off-camera preparation for a lab recording on a fresh GitHub-hosted Ubuntu runner.
# Creates the real login user "thesecguy" on host "lab", then (for setup recordings) removes the
# runner's preinstalled Docker so the install the video shows really happens. Run with sudo.
set -euo pipefail
scenario="$1"
clean=$(python3 -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1])).get("remove_preinstalled", [])))' "$scenario")

hostnamectl set-hostname lab 2>/dev/null || hostname lab
grep -q ' lab$' /etc/hosts || echo "127.0.1.1 lab" >> /etc/hosts

id thesecguy >/dev/null 2>&1 || useradd -m -s /bin/bash thesecguy
# Ephemeral VM, deleted after the run: no password prompts, so the recording never waits on one.
echo 'thesecguy ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/thesecguy
chmod 440 /etc/sudoers.d/thesecguy
# Ubuntu's own coloured prompt (thesecguy@lab:~$), nothing invented.
sed -i 's/^#force_color_prompt=yes/force_color_prompt=yes/' /home/thesecguy/.bashrc
sudo -iu thesecguy git config --global init.defaultBranch main

for tool in $clean; do
  case "$tool" in
    docker)
      systemctl stop docker.socket docker containerd 2>/dev/null || true
      pkgs=$(dpkg -l | awk '$1=="ii" && $2 ~ /^(docker|moby|containerd)/ {print $2}')
      [ -n "$pkgs" ] && DEBIAN_FRONTEND=noninteractive apt-get purge -y $pkgs >/dev/null
      rm -rf /var/lib/docker /etc/docker
      ! command -v docker || { echo "docker still present: $(command -v docker)"; exit 1; } ;;
    ollama)
      ! command -v ollama || { echo "ollama is preinstalled, remove it first"; exit 1; } ;;
  esac
done

# Steps a scenario wants done before the camera starts (e.g. "setup already done" for later labs).
python3 -c 'import json,sys; [print(c) for c in json.load(open(sys.argv[1])).get("before", [])]' "$scenario" |
while IFS= read -r cmd; do
  echo "[before, as thesecguy] $cmd"
  sudo -iu thesecguy bash -lc "$cmd"
done
# Services a scenario needs must answer before the camera starts (off camera, so a take never shows a dead server).
needs=$(python3 -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1])).get("needs", [])))' "$scenario")
for svc in $needs; do
  case "$svc" in
    ollama)
      systemctl start ollama 2>/dev/null || true
      for i in $(seq 1 60); do curl -fsS http://127.0.0.1:11434/api/version >/dev/null 2>&1 && break; sleep 2; done
      curl -fsS http://127.0.0.1:11434/api/version || { echo "ollama is not answering"; systemctl status ollama --no-pager || true; journalctl -u ollama --no-pager | tail -40 || true; exit 1; } ;;
  esac
done
echo "prepared: user thesecguy on host $(hostname), removed: ${clean:-nothing}, ready: ${needs:-nothing}"
