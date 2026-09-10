from __future__ import annotations

import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path

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

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    for marker in ("LICENSE", "NOTICE.md", "THIRD_PARTY_NOTICES.md", "third_party"):
        _require(marker in dockerfile, f"Dockerfile does not preserve legal material: {marker}")

    print("legal policy and license checks passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(f"legal check error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
