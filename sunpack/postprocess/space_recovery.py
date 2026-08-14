from sunpack.contracts.run_context import RunContext
from sunpack.postprocess.actions import PostProcessActions


class ArchiveSpaceRecovery:
    def __init__(self, context: RunContext, actions: PostProcessActions):
        self.context = context
        self.actions = actions

    def cleanup_next_archive_group(self) -> bool:
        if self.actions.cleanup_mode == "keep":
            print(self.actions.t("space.full_keep"), file=self.actions.stdout, flush=True)
            return False

        if not self.context.unpacked_archives:
            print(self.actions.t("space.full_no_archives"), file=self.actions.stdout, flush=True)
            return False

        parts_to_delete = self.context.unpacked_archives.pop(0)
        for path in parts_to_delete:
            self.actions.cleanup_archive_file(path, self.actions.t("space.freeing"))
        return True
