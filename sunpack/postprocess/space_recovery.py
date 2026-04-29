from sunpack.contracts.run_context import RunContext
from sunpack.postprocess.actions import PostProcessActions


class ArchiveSpaceRecovery:
    def __init__(self, context: RunContext, actions: PostProcessActions):
        self.context = context
        self.actions = actions

    def cleanup_next_archive_group(self) -> bool:
        if self.actions.cleanup_mode == "keep":
            print("[CRITICAL] Disk is full, but config is set to keep original archives. Cannot free space.")
            return False

        if not self.context.unpacked_archives:
            print("[CRITICAL] Disk is full, no archives left to delete!")
            return False

        parts_to_delete = self.context.unpacked_archives.pop(0)
        for path in parts_to_delete:
            self.actions.cleanup_archive_file(path, "[SPACE] Freeing space: ")
        return True
