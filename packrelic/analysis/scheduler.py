from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from packrelic.analysis.config import analysis_config, enabled_fuzzy_module_configs, enabled_module_configs
from packrelic.analysis.fuzzy_pipeline.registry import discover_fuzzy_analysis_modules, get_fuzzy_analysis_module_registry
from packrelic.analysis.structure_pipeline.prepass import run_signature_prepass
from packrelic.analysis.structure_pipeline.registry import discover_analysis_modules, get_analysis_module_registry
from packrelic.analysis.result import ArchiveAnalysisReport, ArchiveFormatEvidence
from packrelic.analysis.view import MultiVolumeBinaryView, PatchedBinaryView, SharedBinaryView
from packrelic.contracts.archive_input import ArchiveInputDescriptor
from packrelic.contracts.archive_state import ArchiveState


class ArchiveAnalysisScheduler:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = analysis_config(config or {})
        discover_fuzzy_analysis_modules()
        discover_analysis_modules()

    def analyze_path(self, path: str) -> ArchiveAnalysisReport:
        return self.analyze_view(self._build_single_view(path), report_path=path)

    def analyze_paths(self, paths, *, report_path: str | None = None) -> ArchiveAnalysisReport:
        volumes = list(paths or [])
        if len(volumes) == 1 and not isinstance(volumes[0], dict):
            return self.analyze_path(str(volumes[0]))
        view = self._build_multi_volume_view(volumes)
        return self.analyze_view(view, report_path=report_path or str(view.path))

    def analyze_relation_group(self, group) -> ArchiveAnalysisReport:
        volumes = getattr(group, "split_volumes", None)
        if volumes:
            paths = [
                {
                    "path": volume.path,
                    "number": volume.number,
                }
                for volume in volumes
            ]
            return self.analyze_paths(paths, report_path=getattr(group, "head_path", None))
        return self.analyze_paths(getattr(group, "all_paths", None) or [group.head_path], report_path=getattr(group, "head_path", None))

    def analyze_task(self, task) -> ArchiveAnalysisReport:
        archive_input_report = self._analyze_archive_state(task)
        if archive_input_report is None:
            archive_input_report = self._analyze_archive_input(task)
        if archive_input_report is not None:
            return archive_input_report
        volumes = list(getattr(getattr(task, "split_info", None), "volumes", None) or [])
        if volumes:
            return self.analyze_paths(volumes, report_path=getattr(task, "main_path", None))
        paths = list(getattr(getattr(task, "split_info", None), "parts", None) or getattr(task, "all_parts", None) or [])
        if paths:
            return self.analyze_paths(paths, report_path=getattr(task, "main_path", None))
        return self.analyze_path(task.main_path)

    def _analyze_archive_state(self, task) -> ArchiveAnalysisReport | None:
        fact_bag = getattr(task, "fact_bag", None)
        raw = fact_bag.get("archive.state") if fact_bag is not None and hasattr(fact_bag, "get") else None
        if not isinstance(raw, dict):
            return None
        try:
            state = task.archive_state() if hasattr(task, "archive_state") else self._normalize_archive_state(raw, task)
        except (TypeError, ValueError):
            return None
        if state is None:
            return None
        if state.patches:
            return self.analyze_view(PatchedBinaryView(state), report_path=state.source.entry_path or getattr(task, "main_path", None))
        return self._analyze_descriptor(state.to_archive_input_descriptor(), task)

    def _analyze_archive_input(self, task) -> ArchiveAnalysisReport | None:
        fact_bag = getattr(task, "fact_bag", None)
        raw = fact_bag.get("archive.input") if fact_bag is not None and hasattr(fact_bag, "get") else None
        if not isinstance(raw, dict):
            return None
        if hasattr(task, "archive_input"):
            descriptor = task.archive_input()
        else:
            descriptor = self._normalize_archive_input(raw, task)
            if descriptor is None:
                return None
        return self._analyze_descriptor(descriptor, task)

    def _analyze_descriptor(self, descriptor: ArchiveInputDescriptor, task) -> ArchiveAnalysisReport | None:
        if descriptor.open_mode == "file" and descriptor.entry_path:
            return self.analyze_path(descriptor.entry_path)
        if descriptor.open_mode in {"native_volumes", "staged_volumes", "sfx_with_volumes"} and descriptor.parts:
            paths = [
                {"path": part.path, "number": part.volume_number or index + 1}
                for index, part in enumerate(descriptor.parts)
                if part.path
            ]
            if paths:
                return self.analyze_paths(paths, report_path=descriptor.entry_path or getattr(task, "main_path", None))
        if descriptor.open_mode == "concat_ranges" and descriptor.ranges:
            simple_paths = [
                item.path
                for item in descriptor.ranges
                if item.path and int(item.start) == 0 and item.end is None
            ]
            if simple_paths and len(simple_paths) == len(descriptor.ranges):
                return self.analyze_paths(simple_paths, report_path=descriptor.entry_path or getattr(task, "main_path", None))
        if descriptor.open_mode == "file_range" and descriptor.parts:
            part = descriptor.parts[0]
            item_range = part.range
            if part.path and item_range is not None and int(item_range.start) == 0 and item_range.end is None:
                return self.analyze_path(part.path)
        return None

    def _normalize_archive_state(self, raw: dict, task) -> ArchiveState | None:
        archive_path = str(getattr(task, "main_path", "") or "")
        part_paths = list(getattr(task, "all_parts", None) or [])
        try:
            return ArchiveState.from_any(
                raw,
                archive_path=archive_path,
                part_paths=part_paths,
                format_hint=str(getattr(task, "detected_ext", "") or ""),
                logical_name=str(getattr(task, "logical_name", "") or ""),
            )
        except (TypeError, ValueError):
            return None

    def _normalize_archive_input(self, raw: dict, task) -> ArchiveInputDescriptor | None:
        archive_path = str(getattr(task, "main_path", "") or "")
        part_paths = list(getattr(task, "all_parts", None) or [])
        try:
            if raw.get("kind") == "archive_input" or raw.get("open_mode"):
                return ArchiveInputDescriptor.from_dict(raw, archive_path=archive_path, part_paths=part_paths)
            return ArchiveInputDescriptor.from_source_input(raw, archive_path=archive_path, part_paths=part_paths)
        except (TypeError, ValueError):
            return None

    def analyze_view(self, view: SharedBinaryView | MultiVolumeBinaryView, *, report_path: str | None = None) -> ArchiveAnalysisReport:
        prepass_config = self.config.get("prepass") if isinstance(self.config.get("prepass"), dict) else {}
        prepass = run_signature_prepass(view, prepass_config) if prepass_config.get("enabled", True) else {}
        fuzzy = self._run_fuzzy_pipeline(view, prepass)
        structure_context = {**prepass, "fuzzy": fuzzy}
        modules = self._selected_structure_modules(structure_context)
        evidences = self._run_structure_modules(view, structure_context, modules)
        selected = self._selected_evidences(evidences)
        stats = view.stats()
        return ArchiveAnalysisReport(
            path=report_path or view.path,
            size=view.size,
            evidences=sorted(evidences, key=lambda item: item.confidence, reverse=True),
            selected=selected,
            prepass=prepass,
            fuzzy=fuzzy,
            read_bytes=stats.read_bytes,
            cache_hits=stats.cache_hits,
        )

    def _build_single_view(self, path: str) -> SharedBinaryView:
        cache_bytes = int(self.config.get("shared_cache_mb", 64) or 0) * 1024 * 1024
        max_read_mb = self.config.get("max_read_mb_per_archive", 256)
        max_read_bytes = None if max_read_mb is None else int(max_read_mb) * 1024 * 1024
        return SharedBinaryView(
            path,
            cache_bytes=cache_bytes,
            max_read_bytes=max_read_bytes,
            max_concurrent_reads=int(self.config.get("max_concurrent_reads", 1) or 1),
        )

    def _build_multi_volume_view(self, paths) -> MultiVolumeBinaryView:
        cache_bytes = int(self.config.get("shared_cache_mb", 64) or 0) * 1024 * 1024
        max_read_mb = self.config.get("max_read_mb_per_archive", 256)
        max_read_bytes = None if max_read_mb is None else int(max_read_mb) * 1024 * 1024
        return MultiVolumeBinaryView(
            paths,
            cache_bytes=cache_bytes,
            max_read_bytes=max_read_bytes,
            max_concurrent_reads=int(self.config.get("max_concurrent_reads", 1) or 1),
        )

    def _run_fuzzy_pipeline(self, view: SharedBinaryView | MultiVolumeBinaryView, prepass: dict) -> dict[str, Any]:
        fuzzy_config = self.config.get("fuzzy") if isinstance(self.config.get("fuzzy"), dict) else {}
        if not fuzzy_config.get("enabled", True):
            return {}
        module_configs = enabled_fuzzy_module_configs(self.config)
        registry = get_fuzzy_analysis_module_registry()
        results = {}
        warnings = []
        for name, module_config in module_configs.items():
            module = registry.get(name)
            if module is None:
                warnings.append(f"{name}: fuzzy analysis module is not registered")
                continue
            try:
                results[name] = module.analyze(view, prepass, module_config)
            except Exception as exc:
                warnings.append(f"{name}: {exc}")
        if warnings:
            results["warnings"] = warnings
        return results

    def _selected_structure_modules(self, prepass: dict):
        enabled_configs = enabled_module_configs(self.config)
        registry = get_analysis_module_registry()
        modules = []
        for name in enabled_configs:
            module = registry.get(name)
            if module is None:
                continue
            modules.append(module)
        return modules

    def _run_structure_modules(self, view: SharedBinaryView, prepass: dict, modules) -> list[ArchiveFormatEvidence]:
        module_configs = enabled_module_configs(self.config)
        if not modules:
            return []
        if not self.config.get("parallel", True) or len(modules) == 1:
            return [self._run_module(module, view, prepass, module_configs.get(module.spec.name, {})) for module in modules]

        max_workers = max(1, int(self.config.get("max_workers", 3) or 1))
        evidences = []
        with ThreadPoolExecutor(max_workers=min(max_workers, len(modules))) as executor:
            futures = {
                executor.submit(self._run_module, module, view, prepass, module_configs.get(module.spec.name, {})): module
                for module in modules
            }
            for future in as_completed(futures):
                evidences.append(future.result())
        return evidences

    def _run_module(self, module, view: SharedBinaryView, prepass: dict, config: dict) -> ArchiveFormatEvidence:
        try:
            return module.analyze(view, prepass, config)
        except Exception as exc:
            fmt = module.spec.formats[0] if module.spec.formats else module.spec.name
            return ArchiveFormatEvidence(
                format=fmt,
                confidence=0.0,
                status="error",
                warnings=[str(exc)],
            )

    def _selected_evidences(self, evidences: list[ArchiveFormatEvidence]) -> list[ArchiveFormatEvidence]:
        thresholds = self.config.get("thresholds") if isinstance(self.config.get("thresholds"), dict) else {}
        extractable = float(thresholds.get("extractable_confidence", 0.85))
        return [
            evidence
            for evidence in evidences
            if evidence.status == "extractable" and evidence.confidence >= extractable and evidence.segments
        ]
