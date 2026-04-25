from smart_unpacker.detection.pipeline.rules.confirmation.seven_zip_validation import SevenZipValidationConfirmationRule
from smart_unpacker.contracts.detection import FactBag


def test_validation_does_not_confirm_executable_container_with_checksum_warning():
    bag = FactBag()
    bag.set("file.container_type", "pe")
    bag.set("7z.validation", {
        "ok": False,
        "command_ok": True,
        "type": "pe",
        "is_executable_container": True,
        "checksum_error": True,
        "warnings": ["Checksum error"],
    })

    effect = SevenZipValidationConfirmationRule().evaluate(bag, {})

    assert effect.decision == "pass"
    assert not bag.has("file.validation_ok")


def test_validation_still_confirms_real_7z_sfx_archive_type():
    bag = FactBag()
    bag.set("7z.validation", {
        "ok": True,
        "command_ok": True,
        "type": "7z",
        "is_executable_container": False,
        "checksum_error": False,
        "warnings": [],
    })

    effect = SevenZipValidationConfirmationRule().evaluate(bag, {})

    assert effect.decision == "confirm"
    assert bag.get("file.validation_ok") is True


def test_validation_still_confirms_real_rar_sfx_archive_type():
    bag = FactBag()
    bag.set("7z.validation", {
        "ok": True,
        "command_ok": True,
        "type": "rar5",
        "is_executable_container": False,
        "checksum_error": False,
        "warnings": [],
    })

    effect = SevenZipValidationConfirmationRule().evaluate(bag, {})

    assert effect.decision == "confirm"
    assert bag.get("file.validation_ok") is True
