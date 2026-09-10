from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_LICENSE_SHA256 = "0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0"
EXPECTED_THIRD_PARTY_LICENSES = {
    "third_party/project-forge/LICENSE": (
        "f260de2811b67f47cee8b1ba14437d1494846ecadef25b9690e3f93f4ada5130"
    ),
    "third_party/uv/LICENSE-MIT": (
        "860e3d7a86b84e6a7012c7a635fc64df475cebc6cce34dfeb73a5982ec58176c"
    ),
    "third_party/uv/LICENSE-APACHE": (
        "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"
    ),
    "third_party/npm/@vue/devtools-api/6.6.4/LICENSE": (
        "050bbca6960784db52ff387271bf2ecc5cbed7cf8581b415d528a6ecb6585015"
    ),
}
EXPECTED_PAYPAL_FUNDING = (
    'custom: ["https://www.paypal.me/yernsun"]'
)
EXPECTED_CONTAINER_BASES = (
    "node:24-bookworm-slim@sha256:2fe369e969550cde8e867afc3fe370b260140cab4a23d467074295b42163d553",
    "ghcr.io/astral-sh/uv:0.12.5@sha256:e85be844203885286c60ffad8a858d48afb6c5a5c237ca0e67f12e74b8f174b1",
    "python:3.13-alpine3.23@sha256:75f27d686432419c9d42420b2b9ef605868c7a0682a6be10a6601fad46c2df01",
)
POLICY_FILES = (
    "README.md",
    "README.zh-CN.md",
    "FAQ.md",
    "FAQ.zh-CN.md",
    "SUPPORT.md",
    "SUPPORT.zh-CN.md",
    "COMMERCIAL_SERVICES.md",
    "COMMERCIAL_SERVICES.zh-CN.md",
    "CONTRIBUTING.md",
    "CONTRIBUTING.zh-CN.md",
    "CLA_POLICY.md",
    "CLA_POLICY.zh-CN.md",
    "SECURITY.md",
    "CONTAINER.md",
    "CONTAINER.zh-CN.md",
    "NOTICE.md",
    "THIRD_PARTY_NOTICES.md",
    "docs/README.md",
    "docs/legal/dependency-compliance.md",
    ".github/pull_request_template.md",
)
MARKDOWN_LINK = re.compile(r"\[[^]]*]\(([^)]+)\)")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _check_local_links(relative_path: str) -> None:
    path = ROOT / relative_path
    for match in MARKDOWN_LINK.finditer(path.read_text(encoding="utf-8")):
        target = match.group(1).strip()
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        target_path = target.split("#", maxsplit=1)[0]
        if not target_path:
            continue
        resolved = (path.parent / target_path).resolve()
        _require(
            resolved.is_relative_to(ROOT), f"link escapes repository: {relative_path}: {target}"
        )
        _require(resolved.exists(), f"broken local link: {relative_path}: {target}")


def main() -> int:
    license_path = ROOT / "LICENSE"
    _require(license_path.is_file(), "LICENSE is missing")
    _require(
        _sha256(license_path) == EXPECTED_LICENSE_SHA256,
        "LICENSE differs from the canonical GNU AGPL version 3 text",
    )

    for relative_path, expected_hash in EXPECTED_THIRD_PARTY_LICENSES.items():
        path = ROOT / relative_path
        _require(path.is_file(), f"third-party license is missing: {relative_path}")
        _require(_sha256(path) == expected_hash, f"third-party license changed: {relative_path}")

    for relative_path in POLICY_FILES:
        path = ROOT / relative_path
        _require(path.is_file(), f"required policy file is missing: {relative_path}")
        _check_local_links(relative_path)

    backend_metadata = tomllib.loads((ROOT / "backend/pyproject.toml").read_text(encoding="utf-8"))
    frontend_metadata = json.loads((ROOT / "frontend/package.json").read_text(encoding="utf-8"))
    frontend_lock = json.loads((ROOT / "frontend/package-lock.json").read_text(encoding="utf-8"))
    _require(
        backend_metadata["project"].get("license") == "AGPL-3.0-only",
        "backend package license must be AGPL-3.0-only",
    )
    _require(
        backend_metadata["project"].get("license-files") == ["LICENSE", "NOTICE.md", "licenses/*"],
        "backend package must include its license and inherited Project Forge notice",
    )
    _require(
        _sha256(ROOT / "backend/LICENSE") == EXPECTED_LICENSE_SHA256,
        "backend LICENSE drifted",
    )
    _require(
        (ROOT / "backend/NOTICE.md").read_bytes() == (ROOT / "NOTICE.md").read_bytes(),
        "backend NOTICE.md drifted from the root notice",
    )
    _require(
        (ROOT / "backend/licenses/Project-Forge-MIT.txt").read_bytes()
        == (ROOT / "third_party/project-forge/LICENSE").read_bytes(),
        "backend Project Forge license copy drifted",
    )
    _require(
        frontend_metadata.get("license") == "AGPL-3.0-only",
        "frontend package license must be AGPL-3.0-only",
    )
    _require(
        frontend_lock["packages"][""].get("license") == "AGPL-3.0-only",
        "frontend lock root license must be AGPL-3.0-only",
    )
    _require(
        "generate-license-bundle.mjs" in frontend_metadata["scripts"]["build"],
        "frontend build must generate the production license bundle",
    )
    _require(
        "npm sbom --sbom-format=spdx" in frontend_metadata["scripts"]["build"],
        "frontend build must generate the complete SPDX build dependency inventory",
    )
    license_bundle = (ROOT / "frontend/scripts/generate-license-bundle.mjs").read_text(
        encoding="utf-8"
    )
    for marker in ("repositoryLegalFiles", "dependency-compliance.md", "third_party"):
        _require(marker in license_bundle, f"frontend legal bundle is missing: {marker}")

    support = (ROOT / "SUPPORT.md").read_text(encoding="utf-8")
    cla_policy = (ROOT / "CLA_POLICY.md").read_text(encoding="utf-8")
    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    funding = (ROOT / ".github/FUNDING.yml").read_text(encoding="utf-8")
    _require("no service-level agreement" in support, "SUPPORT.md must state the no-SLA policy")
    _require("Status: not active" in cla_policy, "CLA policy must state that it is not active")
    _require(
        "must not merge" in contributing,
        "CONTRIBUTING.md must enforce the pre-CLA merge gate",
    )
    active_funding_lines = [
        line for line in funding.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]
    _require(
        active_funding_lines == [EXPECTED_PAYPAL_FUNDING],
        "FUNDING.yml target changed; verify the payee and update the legal policy before release",
    )

    project_version = backend_metadata["project"]["version"]
    locked_backend = next(
        package for package in tomllib.loads((ROOT / "backend/uv.lock").read_text(encoding="utf-8"))["package"]
        if package["name"] == "ops-composer"
    )
    api_source = (ROOT / "backend/src/ops_composer/main.py").read_text(encoding="utf-8")
    system_source = (ROOT / "backend/src/ops_composer/api/system.py").read_text(encoding="utf-8")
    openapi_contract = json.loads(
        (ROOT / "frontend/scripts/openapi/contracts/auth.json").read_text(encoding="utf-8")
    )
    version_values = {
        "backend lock": locked_backend["version"],
        "frontend package": frontend_metadata["version"],
        "frontend lock": frontend_lock["version"],
        "frontend lock root": frontend_lock["packages"][""]["version"],
        "OpenAPI contract": openapi_contract["info"]["version"],
    }
    for source_name, version in version_values.items():
        _require(version == project_version, f"{source_name} version differs from backend project")
    _require(
        f'version="{project_version}"' in api_source,
        "FastAPI version differs from backend project",
    )
    _require(
        f'"version": "{project_version}"' in system_source,
        "system API version differs from backend project",
    )

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    for marker in ("LICENSE", "NOTICE.md", "THIRD_PARTY_NOTICES.md", "CONTAINER.md", "third_party"):
        _require(marker in dockerfile, f"Dockerfile does not preserve legal material: {marker}")
    for base in EXPECTED_CONTAINER_BASES:
        base_pattern = rf"^FROM(?: --platform=\$BUILDPLATFORM)? {re.escape(base)} AS [A-Za-z0-9_-]+$"
        _require(
            re.search(base_pattern, dockerfile, flags=re.MULTILINE) is not None,
            f"container base is not digest-pinned: {base}",
        )
    for marker in (
        'org.opencontainers.image.source="https://github.com/yernsun/ops-composer"',
        'org.opencontainers.image.licenses="AGPL-3.0-only"',
        "frontend-build.spdx.json",
    ):
        _require(marker in dockerfile or marker in frontend_metadata["scripts"]["build"], f"container release metadata is missing: {marker}")

    container_workflow = (ROOT / ".github/workflows/container-image.yml").read_text(
        encoding="utf-8"
    )
    for marker in (
        "ghcr.io/${{ github.repository }}",
        "linux/amd64,linux/arm64",
        "provenance: mode=max",
        "sbom: true",
        "aquasecurity/trivy-action@",
        "actions/attest-build-provenance@",
        "--verify-tag",
    ):
        _require(marker in container_workflow, f"container workflow is missing: {marker}")
    unpinned_action = re.search(r"uses:\s+[^\s@]+@(?![0-9a-f]{40}(?:\s|$))[^\s#]+", container_workflow)
    _require(
        unpinned_action is None,
        f"container workflow action is not pinned to a full commit: {unpinned_action.group(0) if unpinned_action else ''}",
    )

    print("legal policy and license checks passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(f"legal check error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
