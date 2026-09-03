from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import yaml

from ops_composer.domain.ops import ResolvedHost


def build_inventory(
    hosts: tuple[ResolvedHost, ...],
    *,
    secrets: Mapping[str, Mapping[str, str]] | None = None,
) -> dict[str, object]:
    """Build a deterministic snapshot; secrets are supplied only inside the worker."""

    inventory_hosts: dict[str, object] = {}
    for host in hosts:
        variables: dict[str, Any] = dict(host.group_variables)
        variables.update(host.host_variables)
        variables.update(
            {
                "ansible_host": host.address,
                "ansible_port": host.ssh_port,
                "ansible_user": host.credential_username,
                "ansible_python_interpreter": host.python_interpreter or "/usr/bin/python3",
            }
        )
        if host.credential_public_config.get("becomeEnabled"):
            variables["ansible_become"] = True
            variables["ansible_become_method"] = host.credential_public_config.get(
                "becomeMethod", "sudo"
            )
            variables["ansible_become_user"] = host.credential_public_config.get(
                "becomeUser", "root"
            )
        if secrets is not None:
            secret = secrets[str(host.credential_id)]
            variables["ansible_password"] = secret["password"]
            if variables.get("ansible_become"):
                variables["ansible_become_password"] = secret.get(
                    "becomePassword", secret["password"]
                )
        inventory_hosts[host.name] = variables
    return {"all": {"hosts": inventory_hosts}}


def render_inventory(inventory: dict[str, object]) -> str:
    return yaml.safe_dump(
        inventory,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=True,
    )
