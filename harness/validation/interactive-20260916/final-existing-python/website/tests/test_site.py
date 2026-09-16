import importlib.util
import pathlib
import unittest
spec = importlib.util.spec_from_file_location("workshop_site", pathlib.Path("src/site.py"))
site = importlib.util.module_from_spec(spec)
spec.loader.exec_module(site)
class WebsiteTests(unittest.TestCase):
    def test_filter(self):
        result = site.render([{"title":"Safety","category":"ai"},{"title":"Music","category":"arts"}], "ai")
        self.assertIn("Safety", result)
        self.assertNotIn("Music", result)
    def test_escape(self):
        self.assertIn("&lt;script&gt;", site.render([{"title":"<script>","category":"ai"}]))
    def test_empty(self):
        self.assertEqual(site.render([]), "<ul></ul>")
