import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1] / 'src'))
import unittest
from reviewer import scan_file
from pathlib import Path

class TestReviewer(unittest.TestCase):
    def test_detect_sqli(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as td:
            f = Path(td) / "a.py"
            f.write_text('q = "SELECT * FROM t WHERE id=" + user_id\n')
            findings = scan_file(f)
            self.assertTrue(any(x.category == "SQLi" for x in findings))

if __name__ == '__main__':
    unittest.main()
