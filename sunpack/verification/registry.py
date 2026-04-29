from importlib import import_module
from pkgutil import iter_modules
from typing import Callable, Protocol

from sunpack.verification.evidence import VerificationEvidence
from sunpack.verification.result import VerificationStepResult


class VerificationMethod(Protocol):
    name: str

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStepResult:
        ...


VerificationMethodFactory = Callable[[], VerificationMethod]

_REGISTRY: dict[str, VerificationMethodFactory] = {}
_DISCOVERED = False


def register_verification_method(name: str):
    def decorator(factory_or_class):
        method_name = name.strip()
        if not method_name:
            raise ValueError("verification method name must not be empty")
        _REGISTRY[method_name] = factory_or_class
        return factory_or_class

    return decorator


def get_verification_method(name: str) -> VerificationMethod | None:
    discover_verification_methods()
    factory = _REGISTRY.get(name)
    if factory is None:
        return None
    return factory()


def registered_verification_methods() -> dict[str, VerificationMethodFactory]:
    discover_verification_methods()
    return dict(_REGISTRY)


def discover_verification_methods() -> None:
    global _DISCOVERED
    if _DISCOVERED:
        return
    package_name = "sunpack.verification.methods"
    package = import_module(package_name)
    for module_info in iter_modules(package.__path__):
        if not module_info.ispkg:
            import_module(f"{package_name}.{module_info.name}")
    _DISCOVERED = True

