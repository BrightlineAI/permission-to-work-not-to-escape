import unittest
from scope import inherited, permissions, nono_grants


def policy(grants):
    return dict(schema_version=1, policy_id="p", job_id="j", principal="parent",
        allow=[dict(tool="file_access", actions=[a], resources=[p], recipients=[],
                    destinations=[]) for a, p in grants], data_rules={}, approval_rules={},
        delegation=dict(max_depth=1, child_may_expand_authority=False))


class ScopeTests(unittest.TestCase):
    def test_intersection_does_not_widen_read_or_write(self):
        parent = policy([("read", "/fixtures/input"), ("write", "/fixtures/output")])
        default = policy([("read", "/fixtures/input"), ("write", "/fixtures/input"),
                          ("write", "/fixtures/output"), ("read", "/fixtures/secret")])
        child = inherited(parent, default, "worker-1")
        self.assertEqual(permissions(child), permissions(parent))
        self.assertEqual(child["principal"], "worker-1")
        self.assertEqual(child["job_id"], parent["job_id"])

    def test_intersection_also_preserves_worker_restrictions(self):
        child = inherited(policy([("read", "/fixtures/a"), ("read", "/fixtures/b")]),
                          policy([("read", "/fixtures/b")]), "w")
        self.assertEqual(permissions(child), {("read", "/fixtures/b")})

    def test_empty_intersection_refuses_launch(self):
        with self.assertRaises(ValueError):
            inherited(policy([("read", "/fixtures/a")]), policy([("read", "/fixtures/b")]), "w")

    def test_unsupported_and_noncanonical_scopes_rejected(self):
        for path in ["/fixtures/../secret", "/fixtures/*", "/etc/passwd", "/fixtures//a"]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                permissions(policy([("read", path)]))

    def test_file_grants_do_not_grant_parent_directory(self):
        flags = nono_grants(policy([("read", "/fixtures/a"), ("write", "/fixtures/b")]))
        self.assertEqual(flags, ["--read", "/app", "--read-file", "/fixtures/a", "--write-file", "/fixtures/b"])


if __name__ == "__main__":
    unittest.main()
