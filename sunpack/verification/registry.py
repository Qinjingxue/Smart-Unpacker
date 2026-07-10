from typing import Callable, Protocol

from sunpack.verification.evidence import VerificationEvidence
from sunpack.contracts.verification import VerificationStepResult
from sunpack.support.module_discovery import discover_package_modules


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
    discover_package_modules("sunpack.verification.methods")
    _DISCOVERED = True

