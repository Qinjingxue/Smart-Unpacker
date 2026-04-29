from typing import Any

from packrelic.contracts.detection import FactBag
from packrelic.detection.pipeline.facts.context import BatchFactCollectorContext
from packrelic.detection.pipeline.facts.registry import get_registry
from packrelic.detection.pipeline.facts.schema import matches_schema_type
from packrelic.support.path_keys import path_key


class BatchFactProvider:
    def __init__(
        self,
        config: dict[str, Any] | None = None,
        fact_configs: dict[str, dict[str, Any]] | None = None,
        enabled_fact_modules: set[str] | None = None,
        scan_session: Any | None = None,
    ):
        self.registry = get_registry()
        self.config = config or {}
        self.fact_configs = fact_configs or {}
        self.enabled_fact_modules = enabled_fact_modules
        self.scan_session = scan_session

    def prefill_facts(self, fact_bags: list[FactBag], fact_names: set[str]):
        self._prefetch_file_head_facts(fact_bags, fact_names)
        for fact_name in fact_names:
            self.prefill_fact(fact_bags, fact_name)

    def _prefetch_file_head_facts(self, fact_bags: list[FactBag], fact_names: set[str]) -> None:
        if self.scan_session is None or not ({"file.size", "file.magic_bytes"} & set(fact_names)):
            return
        paths = [bag.get("file.path") or "" for bag in fact_bags if bag.get("file.path")]
        if not paths:
            return
        facts_by_key = self.scan_session.file_head_facts_for_paths(
            paths,
            magic_size=16 if "file.magic_bytes" in fact_names else 0,
        )
        for bag in fact_bags:
            path = bag.get("file.path") or ""
            if not path:
                continue
            facts = facts_by_key.get(path_key(path), {})
            size = facts.get("size")
            if isinstance(size, int) and not bag.has("file.size"):
                bag.set("file.size", size)
            mtime_ns = facts.get("mtime_ns")
            if isinstance(mtime_ns, int):
                bag.set("file.mtime_ns", mtime_ns)
            magic = facts.get("magic")
            if "file.magic_bytes" in fact_names and isinstance(magic, bytes) and not bag.has("file.magic_bytes"):
                bag.set("file.magic_bytes", magic[:16])

    def prefill_fact(self, fact_bags: list[FactBag], fact_name: str):
        collector = self.registry.get_batch_collector(fact_name)
        if collector is None:
            return
        if self.enabled_fact_modules is not None:
            module_name = collector.__module__.rsplit(".", 1)[-1]
            if module_name not in self.enabled_fact_modules:
                return

        pending = [
            bag
            for bag in fact_bags
            if not bag.has(fact_name) and not bag.is_missing(fact_name)
        ]
        if not pending:
            return

        context = BatchFactCollectorContext(
            fact_bags=pending,
            fact_name=fact_name,
            config=self.config,
            fact_configs=self.fact_configs,
            scan_session=self.scan_session,
        )
        try:
            collector(context)
        except Exception as exc:
            for bag in pending:
                if not bag.has(fact_name):
                    bag.mark_error(fact_name, f"{type(exc).__name__}: {exc}")
            return

        schema = self.registry.get_schema(fact_name) or {}
        expected_type = schema.get("type")
        for bag in pending:
            if not bag.has(fact_name):
                continue
            value = bag.get(fact_name)
            if not matches_schema_type(value, expected_type):
                bag.unset(fact_name)
                bag.mark_error(
                    fact_name,
                    f"Batch collector returned {type(value).__name__}, expected {expected_type}",
                )
