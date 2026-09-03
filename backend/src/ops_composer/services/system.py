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
        workspace = Path(self._settings.playbook_workspace)
        return {
            "database": {"ok": database_ok},
            "playbookWorkspace": {
                "ok": workspace.is_dir(),
                "readOnlyExpected": True,
                "path": str(workspace),
            },
            "middlewareDependencies": [],
        }
