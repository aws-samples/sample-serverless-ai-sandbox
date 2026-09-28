# kiro-classification: public
"""Git operations wrapper for executing git commands inside a Sandbox.

Usage::

    from agent_sandbox import SandboxClient

    client = SandboxClient(api_url="...", region="us-east-1")
    with client.create_session() as session:
        session.wait_ready()
        session.git.clone("https://github.com/user/repo", "/tmp/repo", depth=1)
        status = session.git.status(cwd="/tmp/repo")
        print(status)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_sandbox.sandbox import CommandResult, SandboxConnection

__all__ = ["GitOperations", "GitStatus"]


@dataclass(frozen=True, slots=True)
class GitStatus:
    """Parsed output of ``git status --porcelain``.

    Attributes
    ----------
    branch:
        Current branch name (or ``"HEAD"`` if detached).
    clean:
        ``True`` if the working tree has no uncommitted changes.
    modified:
        List of modified file paths.
    added:
        List of newly added (staged) file paths.
    deleted:
        List of deleted file paths.
    untracked:
        List of untracked file paths.
    """

    branch: str
    clean: bool
    modified: list[str]
    added: list[str]
    deleted: list[str]
    untracked: list[str]


@dataclass(frozen=True, slots=True)
class GitOperations:
    """Convenience wrapper for git commands inside the Sandbox.

    Parameters
    ----------
    sandbox:
        The ``SandboxConnection`` used to execute git commands.
    """

    sandbox: SandboxConnection

    def clone(
        self,
        url: str,
        path: str,
        *,
        branch: str | None = None,
        depth: int | None = None,
    ) -> CommandResult:
        """Clone a repository.

        Parameters
        ----------
        url:
            Repository URL.
        path:
            Destination path inside the Sandbox.
        branch:
            Branch to clone (default: remote HEAD).
        depth:
            Shallow clone depth.

        Returns
        -------
        CommandResult
        """
        cmd = ["git", "clone"]
        if branch:
            cmd += ["-b", branch]
        if depth is not None:
            cmd += ["--depth", str(depth)]
        cmd += [url, path]
        result = self.sandbox.execute(cmd, timeout_seconds=120)
        if result.exit_code != 0:
            raise RuntimeError(f"git clone failed: {result.stderr}")
        return result

    def init(self, path: str, *, bare: bool = False) -> CommandResult:
        """Initialise a new repository.

        Parameters
        ----------
        path:
            Path for the new repository.
        bare:
            Create a bare repository.

        Returns
        -------
        CommandResult
        """
        cmd = ["git", "init"]
        if bare:
            cmd.append("--bare")
        cmd.append(path)
        result = self.sandbox.execute(cmd, timeout_seconds=10)
        if result.exit_code != 0:
            raise RuntimeError(f"git init failed: {result.stderr}")
        return result

    def add(self, *paths: str, cwd: str = "/tmp", all: bool = False) -> CommandResult:  # nosec B108
        """Stage files.

        Parameters
        ----------
        paths:
            File paths to add (relative to *cwd*).
        cwd:
            Working directory.
        all:
            If ``True``, stage all changes (``git add -A``).

        Returns
        -------
        CommandResult
        """
        cmd = ["git", "add"]
        if all:
            cmd.append("-A")
        else:
            cmd.extend(paths if paths else ["."])
        result = self.sandbox.execute(cmd, cwd=cwd, timeout_seconds=10)
        if result.exit_code != 0:
            raise RuntimeError(f"git add failed: {result.stderr}")
        return result

    def commit(
        self,
        message: str,
        *,
        cwd: str = "/tmp",  # nosec B108
        author_name: str | None = None,
        author_email: str | None = None,
    ) -> CommandResult:
        """Create a commit.

        Parameters
        ----------
        message:
            Commit message.
        cwd:
            Working directory.
        author_name:
            Override author name.
        author_email:
            Override author email.

        Returns
        -------
        CommandResult
        """
        env: dict[str, str] = {}
        if author_name:
            env["GIT_AUTHOR_NAME"] = author_name
            env["GIT_COMMITTER_NAME"] = author_name
        if author_email:
            env["GIT_AUTHOR_EMAIL"] = author_email
            env["GIT_COMMITTER_EMAIL"] = author_email
        cmd = ["git", "commit", "-m", message]
        result = self.sandbox.execute(cmd, cwd=cwd, env=env or None, timeout_seconds=10)
        if result.exit_code != 0:
            raise RuntimeError(f"git commit failed: {result.stderr}")
        return result

    def push(
        self,
        *,
        remote: str = "origin",
        branch: str | None = None,
        cwd: str = "/tmp",  # nosec B108
    ) -> CommandResult:
        """Push to a remote.

        Parameters
        ----------
        remote:
            Remote name.
        branch:
            Branch to push.
        cwd:
            Working directory.

        Returns
        -------
        CommandResult
        """
        cmd = ["git", "push", remote]
        if branch:
            cmd.append(branch)
        result = self.sandbox.execute(cmd, cwd=cwd, timeout_seconds=60)
        if result.exit_code != 0:
            raise RuntimeError(f"git push failed: {result.stderr}")
        return result

    def pull(
        self,
        *,
        remote: str = "origin",
        branch: str | None = None,
        cwd: str = "/tmp",  # nosec B108
    ) -> CommandResult:
        """Pull from a remote.

        Parameters
        ----------
        remote:
            Remote name.
        branch:
            Branch to pull.
        cwd:
            Working directory.

        Returns
        -------
        CommandResult
        """
        cmd = ["git", "pull", remote]
        if branch:
            cmd.append(branch)
        result = self.sandbox.execute(cmd, cwd=cwd, timeout_seconds=60)
        if result.exit_code != 0:
            raise RuntimeError(f"git pull failed: {result.stderr}")
        return result

    def status(self, *, cwd: str = "/tmp") -> GitStatus:  # nosec B108
        """Get the repository status.

        Parameters
        ----------
        cwd:
            Working directory (must be inside a git repo).

        Returns
        -------
        GitStatus
            Parsed status with branch, file lists, and clean flag.
        """
        # Get branch
        branch_result = self.sandbox.execute(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=cwd, timeout_seconds=5,
        )
        branch = branch_result.stdout.strip() if branch_result.exit_code == 0 else "unknown"

        # Get porcelain status
        result = self.sandbox.execute(
            ["git", "status", "--porcelain"], cwd=cwd, timeout_seconds=10,
        )

        modified: list[str] = []
        added: list[str] = []
        deleted: list[str] = []
        untracked: list[str] = []

        for line in result.stdout.strip().split("\n"):
            if not line or len(line) < 3:
                continue
            code = line[:2]
            filepath = line[3:].strip()
            if code.strip() == "??":
                untracked.append(filepath)
            elif "M" in code:
                modified.append(filepath)
            elif "A" in code:
                added.append(filepath)
            elif "D" in code:
                deleted.append(filepath)

        return GitStatus(
            branch=branch,
            clean=len(modified) == 0 and len(added) == 0 and len(deleted) == 0 and len(untracked) == 0,
            modified=modified,
            added=added,
            deleted=deleted,
            untracked=untracked,
        )

    def branches(self, *, cwd: str = "/tmp") -> list[str]:  # nosec B108
        """List branches.

        Parameters
        ----------
        cwd:
            Working directory.

        Returns
        -------
        list[str]
            Branch names.
        """
        result = self.sandbox.execute(
            ["git", "branch", "--list", "--format=%(refname:short)"],
            cwd=cwd,
            timeout_seconds=10,
        )
        if result.exit_code != 0:
            raise RuntimeError(f"git branch failed: {result.stderr}")
        return [b.strip() for b in result.stdout.strip().split("\n") if b.strip()]
