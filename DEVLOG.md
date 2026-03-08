# DEVLOG
- Initialized analyzer core with web/C vulnerability heuristics.
- Added complexity/perf heuristic.
- Added markdown report generation with suggested diff.
- Added unit test + GitHub Actions CI.

## 2026-03-08 Iteration 1
- Added `HardcodedSecret` detection for suspicious inline credentials (`api_key`, `token`, `password`, etc.).
- Reworked performance heuristic to use indentation-aware loop nesting depth instead of raw loop count (reduces false positives on sequential loops).
- Refactored path scanning into `_collect_files` for clarity and safer file filtering.
- Expanded tests:
  - `test_detect_hardcoded_secret`
  - `test_no_perf_finding_for_sequential_loops`
- Local test evidence:
  - Command: `python3 -m unittest discover -s tests -v`
  - Result: `Ran 3 tests in 0.004s` / `OK`
