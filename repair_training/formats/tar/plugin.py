from repair_training.formats.atomic_common import make_training_plugin


def get_training_plugin():
    return make_training_plugin("tar")
