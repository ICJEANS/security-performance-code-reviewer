import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1] / 'src'))
import unittest
from reviewer import scan_file


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
