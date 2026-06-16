from typing import TYPE_CHECKING

from sunpack.repair.model.assets import ModelAsset, ModelAssetRegistry, get_model_asset_registry

if TYPE_CHECKING:
    from sunpack.repair.model.runtime import RepairModelRuntime

__all__ = [
    "ModelAsset",
    "ModelAssetRegistry",
    "RepairModelRuntime",
    "get_model_asset_registry",
]


def __getattr__(name: str):
    if name == "RepairModelRuntime":
        from sunpack.repair.model.runtime import RepairModelRuntime

        return RepairModelRuntime
    raise AttributeError(name)
