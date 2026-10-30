import json
import tempfile
import unittest
from pathlib import Path

from app.storage import append_records, load_records, save_records


class StorageTests(unittest.TestCase):
    def test_append_is_bounded_to_500_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "shadowlens.sqlite3"
            append_records(db, [{"n": i} for i in range(510)])
            records = load_records(db)
            self.assertEqual(len(records), 500)
            self.assertEqual(records[0]["n"], 10)
            self.assertEqual(records[-1]["n"], 509)

    def test_imports_legacy_json_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db, legacy = root / "shadowlens.sqlite3", root / "analyses.json"
            legacy.write_text(json.dumps([{"legacy": True}]), encoding="utf-8")
            self.assertEqual(load_records(db, legacy), [{"legacy": True}])
            append_records(db, [{"new": True}])
            self.assertEqual(load_records(db, legacy), [{"legacy": True}, {"new": True}])

    def test_malformed_legacy_file_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db, legacy = root / "shadowlens.sqlite3", root / "analyses.json"
            legacy.write_text("{not json", encoding="utf-8")
            self.assertEqual(load_records(db, legacy), [])
