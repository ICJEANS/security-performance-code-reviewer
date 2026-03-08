import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1] / 'src'))
import unittest
from reviewer import scan_file, scan_path, to_markdown, Finding


class TestReviewer(unittest.TestCase):
    def test_detect_sqli(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as td:
            f = Path(td) / "a.py"
            f.write_text('q = "SELECT * FROM t WHERE id=" + user_id\n')
            findings = scan_file(f)
            self.assertTrue(any(x.category == "SQLi" for x in findings))

    def test_detect_hardcoded_secret(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as td:
            f = Path(td) / "secret.py"
            f.write_text("API_KEY = '1234567890abcd'\n")
            findings = scan_file(f)
            self.assertTrue(any(x.category == "HardcodedSecret" for x in findings))

    def test_detect_eval_code_injection_pattern(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as td:
            f = Path(td) / "inj.py"
            f.write_text("result = eval(user_input)\n")
            findings = scan_file(f)
            self.assertTrue(any(x.category == "CodeInjection" for x in findings))

    def test_ignore_commented_patterns(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as td:
            f = Path(td) / "comments.py"
            f.write_text("# API_KEY = '1234567890abcd'\n")
            findings = scan_file(f)
            self.assertFalse(any(x.category == "HardcodedSecret" for x in findings))

    def test_scan_path_is_deterministic(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as td:
            p = Path(td)
            (p / "b.py").write_text("API_KEY = '1234567890abcd'\n")
            (p / "a.py").write_text("result = eval(user_input)\n")
            one = [f.file for f in scan_path(str(p))]
            two = [f.file for f in scan_path(str(p))]
            self.assertEqual(one, two)

    def test_detect_path_traversal_pattern(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as td:
            f = Path(td) / "path.py"
            f.write_text("f = open(request.args.get('file'))\n")
            findings = scan_file(f)
            self.assertTrue(any(x.category == "PathTraversal" for x in findings))

    def test_large_file_is_skipped_with_notice(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as td:
            f = Path(td) / "big.py"
            f.write_text("x='a'\n" * 300000)
            findings = scan_file(f)
            self.assertTrue(any("Skipped very large file" in x.message for x in findings))

    def test_scan_path_orders_by_severity(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as td:
            p = Path(td)
            (p / "a.py").write_text("result = eval(user_input)\n")
            (p / "b.py").write_text("while True:\n    break\nwhile True:\n    break\nwhile True:\n    break\n")
            findings = scan_path(str(p))
            self.assertEqual(findings[0].severity, "high")

    def test_markdown_escapes_pipes(self):
        md = to_markdown([Finding("high", "Cat|egory", "msg|text", "a|b.py", 3)])
        self.assertIn("Cat\\|egory", md)
        self.assertIn("a\\|b.py", md)

    def test_no_perf_finding_for_sequential_loops(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as td:
            f = Path(td) / "loops.py"
            f.write_text(
                "for i in range(3):\n"
                "    print(i)\n"
                "for j in range(3):\n"
                "    print(j)\n"
                "while False:\n"
                "    break\n"
            )
            findings = scan_file(f)
            self.assertFalse(any(x.category == "Performance" for x in findings))


if __name__ == '__main__':
    unittest.main()
