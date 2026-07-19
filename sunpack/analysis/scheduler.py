from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import nullcontext
from typing import Any

from sunpack.analysis.config import analysis_config, enabled_fuzzy_module_configs
from sunpack.analysis.fuzzy_pipeline.registry import discover_fuzzy_analysis_modules, get_fuzzy_analysis_module_registry
from sunpack.analysis.structure_pipeline.prepass import extend_signature_prepass_full, run_signature_prepass
from sunpack.analysis.structure_pipeline.registry import discover_analysis_modules, get_analysis_module_registry
from sunpack.analysis.result import ArchiveAnalysisReport, ArchiveFormatEvidence
from sunpack.analysis.view import MultiVolumeBinaryView, PatchedBinaryView, SharedBinaryView
from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.tasks import ArchiveTask
from sunpack.support.module_config import enabled_module_configs


class ArchiveAnalysisScheduler:
    def __init__(self, config: dict[str, Any] | None = None, *, executor_pool=None):
        self.config = analysis_config(config or {})
        self.executor_pool = executor_pool
        discover_fuzzy_analysis_modules()
        discover_analysis_modules()

    def analyze_path(self, path: str, *, initial_prepass: dict | None = None) -> ArchiveAnalysisReport:
        return self.analyze_view(self._build_single_view(path), report_path=path, initial_prepass=initial_prepass)

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

    def analyze_task(self, task: ArchiveTask) -> ArchiveAnalysisReport:
        state = task.archive_state()
        if state.patches:
            return self.analyze_view(PatchedBinaryView(state), report_path=state.source.entry_path or task.main_path)
        report = self._analyze_descriptor(state.to_archive_input_descriptor(), task)
        if report is not None:
            return report
        raise ValueError(f"unsupported archive input mode: {state.source.open_mode}")

    def _analyze_descriptor(self, descriptor: ArchiveInputDescriptor, task) -> ArchiveAnalysisReport | None:
        if descriptor.open_mode == "file" and descriptor.entry_path:
            initial_prepass = _task_detection_prepass(task)
            if initial_prepass is not None:
                return self.analyze_path(descriptor.entry_path, initial_prepass=initial_prepass)
            return self.analyze_path(descriptor.entry_path)
        if descriptor.open_mode in {"native_volumes", "sfx_with_volumes"} and descriptor.parts:
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


    def analyze_view(
        self,
        view: SharedBinaryView | MultiVolumeBinaryView,
        *,
        report_path: str | None = None,
        initial_prepass: dict | None = None,
    ) -> ArchiveAnalysisReport:
        prepass_config = self.config.get("prepass") if isinstance(self.config.get("prepass"), dict) else {}
        prepass = dict(initial_prepass or {})
        if not prepass and prepass_config.get("enabled", True):
            prepass = run_signature_prepass(view, prepass_config)
        fuzzy = self._run_fuzzy_pipeline(view, prepass)
        structure_context = {**prepass, "fuzzy": fuzzy}
        modules = self._selected_structure_modules(structure_context)
        evidences = self._run_structure_modules(view, structure_context, modules)
        selected = self._selected_evidences(evidences)
        if not selected and prepass_config.get("enabled", True):
            extended_prepass = extend_signature_prepass_full(view, prepass, prepass_config)
            if extended_prepass is not prepass:
                prepass = extended_prepass
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
        executor_context = (
            nullcontext(self.executor_pool)
            if self.executor_pool is not None
            else ThreadPoolExecutor(max_workers=min(max_workers, len(modules)))
        )
        with executor_context as executor:
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


def _task_detection_prepass(task) -> dict | None:
    fact_bag = getattr(task, "fact_bag", None)
    if fact_bag is None:
        return None
    value = fact_bag.get("analysis.signature_prepass")
    if not isinstance(value, dict) or not value.get("full_scan_complete"):
        return None
    return dict(value)
