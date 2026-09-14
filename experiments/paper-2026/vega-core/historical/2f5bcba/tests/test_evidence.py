import json

from vega_core.evidence import verify_record, write_protected_record


def test_record_hash_detects_tampering(tmp_path):
    path = write_protected_record(tmp_path, "decision.json", {"allowed": False})
    assert verify_record(path)
    value = json.loads(path.read_text())
    value["allowed"] = True
    path.write_text(json.dumps(value))
    assert not verify_record(path)
