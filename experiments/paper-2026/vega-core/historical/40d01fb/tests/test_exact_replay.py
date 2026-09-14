from vega_core.canonical import canonical_hash


def test_replay_hash_is_identical_across_arms():
    request = {"tool": "x", "arguments": {"b": 2, "a": 1}}
    hashes = {arm: canonical_hash(request) for arm in "ABCD"}
    assert len(set(hashes.values())) == 1
