from __future__ import annotations

import hashlib
import io
import json
import math
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath

from ops_composer.domain.errors import PlaybookProjectInvalidError, ValidationError
from ops_composer.domain.ops import PlaybookRevisionFile

MAX_PROJECT_FILES = 256
MAX_PROJECT_BYTES = 10 * 1024 * 1024
MAX_PROJECT_FILE_BYTES = 1024 * 1024
MAX_PROJECT_PATH_LENGTH = 512
MAX_PROJECT_DEPTH = 16
MAX_ZIP_BYTES = 12 * 1024 * 1024
PROJECT_MANIFEST = ".ops-composer-project.json"
YAML_SUFFIXES = frozenset({".yml", ".yaml"})
FORBIDDEN_COMPONENTS = frozenset(
    {
        ".git",
        ".ssh",
        "collections",
        "library",
        "module_utils",
        "action_plugins",
        "become_plugins",
        "cache_plugins",
        "callback_plugins",
        "cliconf_plugins",
        "connection_plugins",
        "filter_plugins",
        "httpapi_plugins",
        "inventory_plugins",
        "lookup_plugins",
        "netconf_plugins",
        "shell_plugins",
        "strategy_plugins",
        "terminal_plugins",
        "test_plugins",
        "vars_plugins",
    }
)
CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True, slots=True)
class NormalizedProject:
    files: tuple[PlaybookRevisionFile, ...]
    entrypoint: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class ValidatedParameters:
    public_values: dict[str, object]
    secret_values: dict[str, str]
    supplied_names: tuple[str, ...]


def normalize_project_path(raw_path: str) -> str:
    if (
        not raw_path
        or len(raw_path) > MAX_PROJECT_PATH_LENGTH
        or "\\" in raw_path
        or CONTROL_CHARACTERS.search(raw_path)
    ):
        raise PlaybookProjectInvalidError("project contains an invalid path")
    path = PurePosixPath(raw_path)
    parts = path.parts
    if path.is_absolute() or not parts or len(parts) > MAX_PROJECT_DEPTH:
        raise PlaybookProjectInvalidError("project contains an invalid path")
    if any(part in {"", ".", ".."} or part.strip() != part for part in parts):
        raise PlaybookProjectInvalidError("project path traversal is not allowed")
    lowered = tuple(part.casefold() for part in parts)
    if (
        raw_path.casefold() == PROJECT_MANIFEST.casefold()
        or "ansible.cfg" in lowered
        or any(part in FORBIDDEN_COMPONENTS or part.endswith("_plugins") for part in lowered)
        or lowered[-1] in {"inventory", "hosts"}
    ):
        raise PlaybookProjectInvalidError("project contains a forbidden path")
    return path.as_posix()


def normalize_project(files: dict[str, str], entrypoint: str) -> NormalizedProject:
    if not files or len(files) > MAX_PROJECT_FILES:
        raise PlaybookProjectInvalidError(
            "project must contain between 1 and 256 files",
            details={"maxFiles": MAX_PROJECT_FILES},
        )
    normalized: list[PlaybookRevisionFile] = []
    seen: set[str] = set()
    total = 0
    digest = hashlib.sha256()
    for raw_path, content in sorted(files.items(), key=lambda item: item[0].casefold()):
        path = normalize_project_path(raw_path)
        folded = path.casefold()
        if folded in seen:
            raise PlaybookProjectInvalidError("project contains duplicate case-folded paths")
        seen.add(folded)
        normalized_content = content.replace("\r\n", "\n").replace("\r", "\n")
        try:
            encoded = normalized_content.encode("utf-8")
        except UnicodeError as error:
            raise PlaybookProjectInvalidError("project files must contain UTF-8 text") from error
        if not encoded or b"\x00" in encoded or len(encoded) > MAX_PROJECT_FILE_BYTES:
            raise PlaybookProjectInvalidError(
                "project contains an empty, binary, or oversized file"
            )
        total += len(encoded)
        if total > MAX_PROJECT_BYTES:
            raise PlaybookProjectInvalidError(
                "project exceeds the 10 MiB limit",
                details={"maxBytes": MAX_PROJECT_BYTES},
            )
        file_digest = hashlib.sha256(encoded).hexdigest()
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_digest.encode("ascii"))
        digest.update(b"\0")
        normalized.append(
            PlaybookRevisionFile(
                path=path,
                content=normalized_content,
                sha256=file_digest,
                size_bytes=len(encoded),
            )
        )
    normalized_entrypoint = normalize_project_path(entrypoint)
    if PurePosixPath(normalized_entrypoint).suffix.casefold() not in YAML_SUFFIXES:
        raise PlaybookProjectInvalidError("entrypoint must be a YAML file")
    matches = [
        item.path for item in normalized if item.path.casefold() == normalized_entrypoint.casefold()
    ]
    if len(matches) != 1:
        raise PlaybookProjectInvalidError(
            "entrypoint does not identify exactly one project file"
        )
    return NormalizedProject(tuple(normalized), matches[0], digest.hexdigest(), total)


def validate_parameter_schema(schema: dict[str, object] | None) -> dict[str, object]:
    candidate: dict[str, object] = schema or {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    }
    allowed_root = {"type", "properties", "required", "additionalProperties", "description"}
    if set(candidate) - allowed_root:
        raise PlaybookProjectInvalidError(
            "parameter Schema contains unsupported root keywords"
        )
    if candidate.get("type") != "object" or candidate.get("additionalProperties") is not False:
        raise PlaybookProjectInvalidError(
            "parameter Schema must be an object with additionalProperties=false"
        )
    if "description" in candidate and not isinstance(candidate["description"], str):
        raise PlaybookProjectInvalidError("parameter Schema description must be a string")
    properties = candidate.get("properties", {})
    if not isinstance(properties, dict) or len(properties) > MAX_PROJECT_FILES:
        raise PlaybookProjectInvalidError("parameter Schema properties are invalid")
    required = candidate.get("required", [])
    if (
        not isinstance(required, list)
        or len(required) != len(set(item for item in required if isinstance(item, str)))
        or not all(isinstance(item, str) and item in properties for item in required)
    ):
        raise PlaybookProjectInvalidError("parameter Schema required fields are invalid")
    allowed_property = {
        "type",
        "description",
        "default",
        "enum",
        "minimum",
        "maximum",
        "minLength",
        "maxLength",
        "x-ops-composer-sensitive",
    }
    for name, raw_definition in properties.items():
        if not isinstance(name, str) or not name or len(name) > 128:
            raise PlaybookProjectInvalidError("parameter Schema property name is invalid")
        if not isinstance(raw_definition, dict) or set(raw_definition) - allowed_property:
            raise PlaybookProjectInvalidError(
                "parameter Schema property contains unsupported keywords",
                details={"field": name},
            )
        value_type = raw_definition.get("type")
        if value_type not in {"string", "integer", "number", "boolean"}:
            raise PlaybookProjectInvalidError(
                "parameter Schema property type is unsupported", details={"field": name}
            )
        description = raw_definition.get("description")
        if description is not None and not isinstance(description, str):
            raise PlaybookProjectInvalidError(
                "parameter description must be a string", details={"field": name}
            )
        sensitive = raw_definition.get("x-ops-composer-sensitive", False)
        if not isinstance(sensitive, bool):
            raise PlaybookProjectInvalidError(
                "sensitive marker must be boolean", details={"field": name}
            )
        if sensitive and (value_type != "string" or "default" in raw_definition):
            raise PlaybookProjectInvalidError(
                "sensitive parameters must be strings without defaults",
                details={"field": name},
            )
        if "enum" in raw_definition:
            enum = raw_definition["enum"]
            if not isinstance(enum, list) or not enum:
                raise PlaybookProjectInvalidError(
                    "parameter enum is invalid", details={"field": name}
                )
            for item in enum:
                _validate_parameter_type(name, value_type, item)
            if len({json.dumps(item, sort_keys=True) for item in enum}) != len(enum):
                raise PlaybookProjectInvalidError(
                    "parameter enum contains duplicate values", details={"field": name}
                )
        if "default" in raw_definition:
            _validate_parameter_type(name, value_type, raw_definition["default"])
            if (
                "enum" in raw_definition
                and raw_definition["default"] not in raw_definition["enum"]
            ):
                raise PlaybookProjectInvalidError(
                    "parameter default is outside its enum", details={"field": name}
                )
        minimum_length = raw_definition.get("minLength")
        maximum_length = raw_definition.get("maxLength")
        if value_type == "string":
            if not all(
                value is None
                or (isinstance(value, int) and not isinstance(value, bool) and value >= 0)
                for value in (minimum_length, maximum_length)
            ):
                raise PlaybookProjectInvalidError(
                    "string length limits are invalid", details={"field": name}
                )
            if (
                isinstance(minimum_length, int)
                and isinstance(maximum_length, int)
                and minimum_length > maximum_length
            ):
                raise PlaybookProjectInvalidError(
                    "string length limits are reversed", details={"field": name}
                )
        elif minimum_length is not None or maximum_length is not None:
            raise PlaybookProjectInvalidError(
                "length limits require a string parameter", details={"field": name}
            )
        minimum = raw_definition.get("minimum")
        maximum = raw_definition.get("maximum")
        if value_type in {"integer", "number"}:
            if not all(_finite_number(value) for value in (minimum, maximum) if value is not None):
                raise PlaybookProjectInvalidError(
                    "numeric limits are invalid", details={"field": name}
                )
            if minimum is not None and maximum is not None and minimum > maximum:
                raise PlaybookProjectInvalidError(
                    "numeric limits are reversed", details={"field": name}
                )
        elif minimum is not None or maximum is not None:
            raise PlaybookProjectInvalidError(
                "numeric limits require a numeric parameter", details={"field": name}
            )
    try:
        encoded = json.dumps(
            candidate,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise PlaybookProjectInvalidError("parameter Schema must be valid JSON") from error
    if len(encoded.encode("utf-8")) > 64 * 1024:
        raise PlaybookProjectInvalidError("parameter Schema exceeds 64 KiB")
    normalized = json.loads(encoded)
    if not isinstance(normalized, dict):
        raise PlaybookProjectInvalidError("parameter Schema root must be an object")
    return {str(key): value for key, value in normalized.items()}


def _validate_parameter_type(name: str, value_type: object, value: object) -> None:
    valid = (
        isinstance(value, str)
        if value_type == "string"
        else isinstance(value, bool)
        if value_type == "boolean"
        else isinstance(value, int) and not isinstance(value, bool)
        if value_type == "integer"
        else _finite_number(value)
    )
    if not valid:
        raise ValidationError("parameter type is invalid", details={"field": name})


def _finite_number(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and (not isinstance(value, float) or math.isfinite(value))
    )


def validate_parameters(
    schema: dict[str, object], values: dict[str, object]
) -> ValidatedParameters:
    normalized_schema = validate_parameter_schema(schema)
    properties = normalized_schema["properties"]
    assert isinstance(properties, dict)
    raw_required = normalized_schema.get("required", [])
    assert isinstance(raw_required, list)
    required = set(raw_required)
    unexpected = sorted(set(values) - set(properties))
    if unexpected:
        raise ValidationError("unknown Playbook parameters", details={"fields": unexpected})
    public: dict[str, object] = {}
    secret: dict[str, str] = {}
    for name, raw_definition in properties.items():
        assert isinstance(name, str) and isinstance(raw_definition, dict)
        supplied = name in values
        if supplied:
            value = values[name]
        elif "default" in raw_definition:
            value = raw_definition["default"]
        elif name in required:
            raise ValidationError("required Playbook parameter is missing", details={"field": name})
        else:
            continue
        value_type = raw_definition["type"]
        _validate_parameter_type(name, value_type, value)
        if "enum" in raw_definition and value not in raw_definition["enum"]:
            raise ValidationError("Playbook parameter is outside its enum", details={"field": name})
        if isinstance(value, str):
            minimum = raw_definition.get("minLength")
            maximum = raw_definition.get("maxLength")
            if isinstance(minimum, int) and len(value) < minimum:
                raise ValidationError("Playbook parameter is too short", details={"field": name})
            if isinstance(maximum, int) and len(value) > maximum:
                raise ValidationError("Playbook parameter is too long", details={"field": name})
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            minimum = raw_definition.get("minimum")
            maximum = raw_definition.get("maximum")
            if isinstance(minimum, (int, float)) and value < minimum:
                raise ValidationError(
                    "Playbook parameter is below minimum", details={"field": name}
                )
            if isinstance(maximum, (int, float)) and value > maximum:
                raise ValidationError(
                    "Playbook parameter is above maximum", details={"field": name}
                )
        if raw_definition.get("x-ops-composer-sensitive"):
            assert isinstance(value, str)
            secret[name] = value
        else:
            public[name] = value
    return ValidatedParameters(public, secret, tuple(sorted(values)))


def import_project_zip(payload: bytes, explicit_entrypoint: str | None) -> NormalizedProject:
    if not payload or len(payload) > MAX_ZIP_BYTES:
        raise PlaybookProjectInvalidError("ZIP archive is empty or exceeds the upload limit")
    try:
        archive = zipfile.ZipFile(io.BytesIO(payload))
    except (OSError, zipfile.BadZipFile) as error:
        raise PlaybookProjectInvalidError("ZIP archive is invalid") from error
    files: dict[str, str] = {}
    manifest_entrypoint: str | None = None
    actual_total = 0
    with archive:
        members = [member for member in archive.infolist() if not member.is_dir()]
        if len(members) > MAX_PROJECT_FILES + 1:
            raise PlaybookProjectInvalidError("ZIP archive contains too many files")
        seen: set[str] = set()
        for member in members:
            if member.flag_bits & 0x1:
                raise PlaybookProjectInvalidError("encrypted ZIP entries are not supported")
            file_type = (member.external_attr >> 16) & 0o170000
            if file_type == stat.S_IFLNK:
                raise PlaybookProjectInvalidError("ZIP symbolic links are not supported")
            permissions = (member.external_attr >> 16) & 0o777
            if permissions & 0o111:
                raise PlaybookProjectInvalidError("ZIP executable files are not supported")
            if file_type not in {0, stat.S_IFREG}:
                raise PlaybookProjectInvalidError("ZIP special files are not supported")
            if member.file_size > MAX_PROJECT_FILE_BYTES:
                raise PlaybookProjectInvalidError("ZIP archive contains an oversized file")
            path = (
                member.filename
                if member.filename == PROJECT_MANIFEST
                else normalize_project_path(member.filename)
            )
            folded = path.casefold()
            if folded in seen:
                raise PlaybookProjectInvalidError("ZIP archive contains duplicate paths")
            seen.add(folded)
            chunks: list[bytes] = []
            member_size = 0
            with archive.open(member, "r") as source:
                while chunk := source.read(64 * 1024):
                    member_size += len(chunk)
                    actual_total += len(chunk)
                    if member_size > MAX_PROJECT_FILE_BYTES or actual_total > MAX_PROJECT_BYTES:
                        raise PlaybookProjectInvalidError(
                            "ZIP archive exceeds extraction limits"
                        )
                    chunks.append(chunk)
            try:
                text = b"".join(chunks).decode("utf-8")
            except UnicodeError as error:
                raise PlaybookProjectInvalidError(
                    "ZIP project files must contain UTF-8 text"
                ) from error
            if path == PROJECT_MANIFEST:
                try:
                    manifest = json.loads(text)
                except json.JSONDecodeError as error:
                    raise PlaybookProjectInvalidError("project manifest is invalid") from error
                if not isinstance(manifest, dict) or not isinstance(
                    manifest.get("entrypoint"), str
                ):
                    raise PlaybookProjectInvalidError("project manifest is invalid")
                manifest_entrypoint = manifest["entrypoint"]
            else:
                files[path] = text
    entrypoint = explicit_entrypoint or manifest_entrypoint
    if entrypoint is None:
        raise PlaybookProjectInvalidError(
            "entrypoint must be selected for ZIP archives without a manifest"
        )
    return normalize_project(files, entrypoint)


def export_project_zip(project: NormalizedProject) -> bytes:
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        manifest = json.dumps(
            {"formatVersion": 1, "entrypoint": project.entrypoint},
            sort_keys=True,
            separators=(",", ":"),
        )
        entries = [(PROJECT_MANIFEST, manifest)] + [
            (item.path, item.content) for item in project.files
        ]
        for path, content in entries:
            info = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            info.create_system = 3
            archive.writestr(info, content.encode("utf-8"))
    return target.getvalue()
