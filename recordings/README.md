# Lab recordings

The terminal parts of the course's lab videos are recorded here, for real.

- `record-lab` (GitHub Actions) starts a fresh Ubuntu machine, creates the user `thesecguy` on host `lab`, and runs the lab's commands in a real terminal. Nothing is typed by hand and nothing is edited: the recording is what the terminal printed.
- Each scenario in `scenarios/` lists the commands, in the order the lesson gives them, and the answers to the questions the setup script asks.
- Setup recordings first remove the Docker that GitHub's machines come with, so the install you see in the video really happens.
- The run log on GitHub shows the whole session as text, and the fingerprints (SHA-256) of the files the video is made from.

The video only speeds up long waits (downloads, installs). When it does, the screen says so.
