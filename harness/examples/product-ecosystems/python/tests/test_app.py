import unittest
from src.app import add


class Addition(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(20, 22), 42)
        self.assertEqual(add(-1, 1), 0)

    def test_reject_text(self):
        with self.assertRaises(TypeError):
            add("20", 22)
