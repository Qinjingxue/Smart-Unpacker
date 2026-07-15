from sunpack.support.output_inventory import OutputInventory, collect_output_inventory


def test_complete_worker_inventory_reuses_manifest_file_objects(tmp_path):
    file_row = {
        "index": 0,
        "path": "source.txt",
        "output_path": "decoded.txt",
        "size": 3,
        "bytes_written": 3,
        "has_crc": True,
        "crc32": 7,
        "has_output_crc": True,
        "output_crc32": 7,
        "crc_ok": True,
        "status": "complete",
    }
    worker_result = {
        "status": "ok",
        "verified_manifest": {
            "validated": True,
            "files": [file_row],
            "inventory": {
                "complete": True,
                "file_count": 1,
                "dir_count": 0,
                "total_size": 3,
                "identity_paths": False,
            },
        },
    }

    inventory = collect_output_inventory(str(tmp_path), worker_result)

    assert inventory.files[0] is file_row
    assert inventory.stats.relative_paths == ("decoded.txt",)
    assert OutputInventory.from_value(inventory, expected_root=str(tmp_path)) is inventory
