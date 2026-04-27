from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from smart_unpacker.analysis.config import analysis_config, enabled_module_configs
from smart_unpacker.analysis.pipeline.prepass import run_signature_prepass
from smart_unpacker.analysis.pipeline.registry import discover_analysis_modules, get_analysis_module_registry
from smart_unpacker.analysis.result import ArchiveAnalysisReport, ArchiveFormatEvidence
from smart_unpacker.analysis.view import MultiVolumeBinaryView, SharedBinaryView


class ArchiveAnalysisScheduler:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = analysis_config(config or {})
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
        volumes = list(getattr(getattr(task, "split_info", None), "volumes", None) or [])
        if volumes:
            return self.analyze_paths(volumes, report_path=getattr(task, "main_path", None))
        paths = list(getattr(getattr(task, "split_info", None), "parts", None) or getattr(task, "all_parts", None) or [])
        if paths:
            return self.analyze_paths(paths, report_path=getattr(task, "main_path", None))
        return self.analyze_path(task.main_path)

    def analyze_view(self, view: SharedBinaryView | MultiVolumeBinaryView, *, report_path: str | None = None) -> ArchiveAnalysisReport:
        prepass_config = self.config.get("prepass") if isinstance(self.config.get("prepass"), dict) else {}
        prepass = run_signature_prepass(view, prepass_config) if prepass_config.get("enabled", True) else {}
        modules = self._selected_modules(prepass)
        evidences = self._run_modules(view, prepass, modules)
        selected = self._selected_evidences(evidences)
        stats = view.stats()
        return ArchiveAnalysisReport(
            path=report_path or view.path,
            size=view.size,
            evidences=sorted(evidences, key=lambda item: item.confidence, reverse=True),
            selected=selected,
            prepass=prepass,
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

    def _selected_modules(self, prepass: dict):
        enabled_configs = enabled_module_configs(self.config)
        registry = get_analysis_module_registry()
        modules = []
        for name in enabled_configs:
            module = registry.get(name)
            if module is None:
                continue
            modules.append(module)
        return modules

    def _run_modules(self, view: SharedBinaryView, prepass: dict, modules) -> list[ArchiveFormatEvidence]:
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
