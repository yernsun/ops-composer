from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import yaml

from ops_composer.domain.errors import NotFoundError, ValidationError
from ops_composer.domain.ops import Playbook


class PlaybookCatalog:
    def __init__(self, workspace: Path) -> None:
        self._workspace = workspace.resolve()
        self._playbooks = self._workspace / "playbooks"

    def resolve(self, requested_path: str) -> Path:
        candidate = Path(requested_path)
        if candidate.is_absolute() or candidate.suffix.casefold() not in {".yml", ".yaml"}:
            raise ValidationError("playbook path must be a relative .yml or .yaml file")
        resolved = (self._workspace / candidate).resolve()
        try:
            resolved.relative_to(self._playbooks.resolve())
        except ValueError as error:
            raise ValidationError(
                "playbook path escapes the read-only playbook directory"
            ) from error
        if not resolved.is_file():
            raise NotFoundError("playbook not found")
        return resolved

    @staticmethod
    def _describe(path: Path, workspace: Path) -> Playbook:
        data = path.read_bytes()
        stat = path.stat()
        return Playbook(
            path=path.relative_to(workspace).as_posix(),
            name=path.stem.replace("-", " ").replace("_", " ").title(),
            size=len(data),
            modified_at=__import__("datetime").datetime.fromtimestamp(
                stat.st_mtime, __import__("datetime").UTC
            ),
            sha256=hashlib.sha256(data).hexdigest(),
        )

    async def list(self) -> tuple[Playbook, ...]:
        if not self._playbooks.is_dir():
            return ()
        paths = sorted(
            {
                *self._playbooks.rglob("*.yml"),
                *self._playbooks.rglob("*.yaml"),
            }
        )
        valid: list[Playbook] = []
        for path in paths:
            try:
                resolved = self.resolve(path.relative_to(self._workspace).as_posix())
                document = yaml.safe_load(resolved.read_text(encoding="utf-8"))
                if isinstance(document, list):
                    valid.append(self._describe(resolved, self._workspace))
            except (OSError, UnicodeError, yaml.YAMLError, ValidationError):
                continue
        return tuple(valid)

    async def get(self, requested_path: str) -> Playbook:
        path = self.resolve(requested_path)
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as error:
            raise ValidationError("playbook YAML is invalid") from error
        if not isinstance(document, list):
            raise ValidationError("playbook root must be a list of plays")
        return self._describe(path, self._workspace)

    async def syntax_check(self, requested_path: str) -> tuple[bool, str]:
        path = self.resolve(requested_path)
        try:
            process = await asyncio.create_subprocess_exec(
                "ansible-playbook",
                "--syntax-check",
                str(path),
                cwd=self._workspace,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            output, _ = await asyncio.wait_for(process.communicate(), timeout=30)
        except FileNotFoundError as error:
            raise ValidationError("ansible-playbook is not installed") from error
        except TimeoutError:
            return False, "syntax check timed out"
        text = output.decode("utf-8", errors="replace")[-16384:]
        return process.returncode == 0, text
