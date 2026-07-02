from __future__ import annotations

import json
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sunpack.repair.config import repair_system_mode
from sunpack.support.archive_formats import canonical_format as _normalize_format
from sunpack.support.resources import candidate_resource_roots, find_resource_path


MODEL_MANIFEST_NAME = "models/manifest.json"


@dataclass(frozen=True)
class ModelAsset:
    format: str
    role: str
    model_dir: Path
    model_type: str
    semantics: str
    algorithm: str
    expected_model_type: str = ""
    expected_semantics: str = ""
    expected_sha256: str = ""

    @property
    def available(self) -> bool:
        return (
            (self.model_dir / "model.pt").is_file()
            and (self.model_dir / "model_card.json").is_file()
            and not self.validation_errors
        )

    @property
    def validation_errors(self) -> list[str]:
        errors = []
        if self.expected_model_type and self.model_type != self.expected_model_type:
            errors.append(f"model_type mismatch: expected {self.expected_model_type}, got {self.model_type or '<missing>'}")
        if self.expected_semantics and self.semantics != self.expected_semantics:
            errors.append(f"semantics mismatch: expected {self.expected_semantics}, got {self.semantics or '<missing>'}")
        if self.expected_sha256 and (self.model_dir / "model.pt").is_file():
            actual = _sha256(self.model_dir / "model.pt")
            if actual != self.expected_sha256:
                errors.append(f"model sha256 mismatch: expected {self.expected_sha256}, got {actual}")
        return errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "role": self.role,
            "model_dir": str(self.model_dir),
            "model_type": self.model_type,
            "semantics": self.semantics,
            "algorithm": self.algorithm,
            "available": self.available,
            "validation_errors": self.validation_errors,
        }


class ModelAssetRegistry:
    def __init__(self, manifest_path: str | Path | None = None):
        self.manifest_path = Path(manifest_path).resolve() if manifest_path else _find_manifest()
        self.payload = _read_json(self.manifest_path) if self.manifest_path else {}

    def supported_formats(self) -> list[str]:
        formats = self.payload.get("formats") if isinstance(self.payload.get("formats"), dict) else {}
        return sorted(str(name) for name in formats)

    def asset(self, format_name: str, role: str) -> ModelAsset | None:
        fmt = _normalize_format(format_name)
        role = str(role or "").strip().lower()
        env_path = _environment_override(role)
        entry = self._entry(fmt, role)
        if entry is None and not env_path:
            return None
        model_dir = Path(env_path).resolve() if env_path else self._resolve_entry_path(entry or {})
        card = _read_json(model_dir / "model_card.json")
        return ModelAsset(
            format=fmt,
            role=role,
            model_dir=model_dir,
            model_type=str(card.get("model_type") or (entry or {}).get("model_type") or ""),
            semantics=str(
                card.get("diagnosis_semantics")
                or card.get("policy_semantics")
                or (entry or {}).get("semantics")
                or ""
            ),
            algorithm=str(card.get("algorithm") or (entry or {}).get("algorithm") or ""),
            expected_model_type=str((entry or {}).get("model_type") or ""),
            expected_semantics=str((entry or {}).get("semantics") or ""),
            expected_sha256=str((entry or {}).get("sha256") or "").lower(),
        )

    def status(self, *, load: bool = False, device: str = "cpu") -> dict[str, Any]:
        if repair_system_mode() == "lite":
            return {
                "manifest": str(self.manifest_path or ""),
                "supported_formats": [],
                "models": [],
                "ok": True,
                "repair_system": "lite",
                "disabled_reason": "repair system is not included in this build",
            }
        rows: list[dict[str, Any]] = []
        for fmt in self.supported_formats():
            for role in ("diagnosis", "policy"):
                asset = self.asset(fmt, role)
                row = {"format": fmt, "role": role, "available": False}
                if asset is not None:
                    row.update(asset.to_dict())
                    row["loaded"] = False
                    if load and asset.available:
                        try:
                            _load_asset(asset, device=device)
                            row["loaded"] = True
                        except Exception as exc:
                            row["load_error"] = str(exc)
                rows.append(row)
        return {
            "manifest": str(self.manifest_path or ""),
            "supported_formats": self.supported_formats(),
            "models": rows,
            "ok": bool(rows) and all(
                bool(row.get("loaded") if load else row.get("available"))
                for row in rows
            ),
        }

    def _entry(self, fmt: str, role: str) -> dict[str, Any] | None:
        formats = self.payload.get("formats") if isinstance(self.payload.get("formats"), dict) else {}
        format_payload = formats.get(fmt) if isinstance(formats.get(fmt), dict) else {}
        entry = format_payload.get(role)
        if not isinstance(entry, dict):
            shared = self.payload.get("shared") if isinstance(self.payload.get("shared"), dict) else {}
            entry = shared.get(role)
        return dict(entry) if isinstance(entry, dict) else None

    def _resolve_entry_path(self, entry: dict[str, Any]) -> Path:
        packaged = str(entry.get("packaged_path") or "")
        if packaged:
            for root in candidate_resource_roots():
                candidate = root / packaged
                if candidate.is_dir():
                    return candidate.resolve()
        return Path(packaged or ".").resolve()


_REGISTRY: ModelAssetRegistry | None = None


def get_model_asset_registry(*, refresh: bool = False) -> ModelAssetRegistry:
    global _REGISTRY
    if refresh or _REGISTRY is None:
        _REGISTRY = ModelAssetRegistry()
    return _REGISTRY


def _find_manifest() -> Path | None:
    override = os.environ.get("SUNPACK_MODEL_MANIFEST", "").strip()
    if override:
        path = Path(override).resolve()
        return path if path.is_file() else None
    return find_resource_path(MODEL_MANIFEST_NAME)


def _environment_override(role: str) -> str:
    key = {
        "diagnosis": "SUNPACK_DIAGNOSIS_GNN_MODEL_DIR",
        "policy": "SUNPACK_POLICY_TRANSFORMER_MODEL_DIR",
    }.get(role, "")
    return os.environ.get(key, "").strip() if key else ""


def _load_asset(asset: ModelAsset, *, device: str) -> Any:
    if asset.role == "diagnosis":
        from sunpack.repair.model.diagnosis.inference import DiagnosisGNNModel

        return DiagnosisGNNModel(model_dir=asset.model_dir, device=device)
    if asset.role == "policy":
        from sunpack.repair.model.policy.inference import RepairPolicyTransformerModel

        return RepairPolicyTransformerModel(model_dir=asset.model_dir, device=device)
    raise RuntimeError(f"unsupported model role: {asset.role}")


def _read_json(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
