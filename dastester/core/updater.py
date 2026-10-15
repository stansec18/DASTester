"""Self-update mechanism for `dastester --update`.

Two strategies, tried in order:

1. Git: if DASTester is running from inside a git working tree, run
   `git pull --ff-only` against the configured branch. This is the
   recommended install method.
2. Pip/GitHub: otherwise, upgrade from the configured GitHub repository
   using pip (`pip install --upgrade git+<repo>`).

The update source is configurable in one place (config file / env var)
so you can point it at your own fork.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Configure your repository here (or override with the DASTESTER_REPO env var).
# Replace <your-org-or-user> once you have pushed DASTester to GitHub.
# ---------------------------------------------------------------------------
DEFAULT_REPO = "https://github.com/<your-org-or-user>/dastester.git"
DEFAULT_BRANCH = "main"


def _repo() -> str:
    return os.environ.get("DASTESTER_REPO", DEFAULT_REPO)


def _branch() -> str:
    return os.environ.get("DASTESTER_BRANCH", DEFAULT_BRANCH)


def _package_root() -> Path:
    # .../dastester/core/updater.py -> project root is two parents up.
    return Path(__file__).resolve().parents[2]


def _is_git_tree(path: Path) -> bool:
    return (path / ".git").exists()


def _run(cmd, cwd=None):
    print(f"  $ {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def update(logger=print) -> int:
    root = _package_root()
    branch = _branch()

    if _is_git_tree(root):
        logger(f"Updating via git in {root} (branch: {branch})...")
        fetch = _run(["git", "fetch", "origin", branch], cwd=str(root))
        if fetch.returncode != 0:
            logger("git fetch failed:\n" + fetch.stderr.strip())
            return 1
        pull = _run(["git", "pull", "--ff-only", "origin", branch], cwd=str(root))
        logger(pull.stdout.strip() or pull.stderr.strip())
        if pull.returncode != 0:
            logger(
                "Fast-forward update failed. You may have local changes; "
                "resolve them and retry, or re-clone."
            )
            return pull.returncode
        logger("Update complete. Run 'pip install -r requirements.txt' if "
               "dependencies changed.")
        return 0

    # Not a git tree: upgrade from the configured GitHub repo via pip.
    repo = _repo()
    if "<your-org-or-user>" in repo:
        logger(
            "No update source configured. Set the DASTESTER_REPO environment "
            "variable to your GitHub repo URL, or edit DEFAULT_REPO in "
            "dastester/core/updater.py, then re-run 'dastester --update'."
        )
        return 2
    logger(f"Updating from {repo} via pip...")
    res = _run([
        sys.executable, "-m", "pip", "install", "--upgrade",
        f"git+{repo}@{branch}",
    ])
    logger(res.stdout.strip() or res.stderr.strip())
    return res.returncode
