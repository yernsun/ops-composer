from __future__ import annotations

from pathlib import Path

from ops_composer.settings import Settings
from ops_composer.uow.factory import UnitOfWorkFactory


class SystemService:
    def __init__(self, unit_of_work_factory: UnitOfWorkFactory, settings: Settings) -> None:
        self._unit_of_work_factory = unit_of_work_factory
        self._settings = settings

    async def doctor(self) -> dict[str, object]:
        try:
            async with self._unit_of_work_factory() as unit_of_work:
                database_ok = await unit_of_work.health.is_ready()
        except Exception:
            database_ok = False
        mode = self._settings.playbook_source_mode
        mount_enabled = mode.mount_enabled
        workspace = Path(self._settings.playbook_workspace)
        mount_directory = workspace / "playbooks"
        mount_ok = mount_directory.is_dir() if mount_enabled else None
        return {
            "database": {"ok": database_ok},
            "playbookWorkspace": {
                "enabled": mount_enabled,
                "checked": mount_enabled,
                "ok": mount_ok,
                "degraded": bool(
                    mode.database_enabled and mount_enabled and not mount_ok
                ),
                "readOnlyExpected": True,
                "path": str(workspace),
                "playbookDirectory": str(mount_directory),
            },
            "playbookSources": {
                "mode": mode.value,
                "database": {
                    "enabled": mode.database_enabled,
                    "writable": mode.database_enabled,
                    "ok": database_ok if mode.database_enabled else None,
                },
                "mount": {
                    "enabled": mount_enabled,
                    "readOnly": True,
                    "ok": mount_ok,
                },
            },
            "middlewareDependencies": [],
        }
