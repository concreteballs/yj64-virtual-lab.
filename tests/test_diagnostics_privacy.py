import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from diagnostics import sanitize_event_data
from yj64_persistent_core import PersistentCore


class DiagnosticPrivacyTests(unittest.TestCase):
    def test_message_and_model_payloads_are_replaced_with_lengths(self):
        safe = sanitize_event_data(
            "participant_request_started",
            {
                "participant": "Participant 1",
                "route_id": "route_1",
                "mode": "text",
                "provider": "gemini",
                "model": "gemini-2.5-flash",
                "prompt": "private user message",
                "response": "private model response",
                "error": "authorization: Bearer very-secret-token",
                "traceback": "private traceback content",
                "private_history_count": 2,
            },
        )
        self.assertEqual(safe["prompt_length"], len("private user message"))
        self.assertEqual(safe["response_length"], len("private model response"))
        self.assertTrue(safe["error_present"])
        self.assertEqual(safe["private_history_count"], 2)
        for forbidden in ("prompt", "response", "error", "traceback"):
            self.assertNotIn(forbidden, safe)
        self.assertNotIn("very-secret-token", json.dumps(safe))

    def test_unknown_fields_and_custom_participant_names_are_dropped(self):
        safe = sanitize_event_data(
            "event",
            {
                "participant": "Alice Smith",
                "endpoint": "https://example.invalid/private?token=secret",
                "custom_field": "private data",
                "pid": 123,
            },
        )
        self.assertEqual(safe, {"pid": 123})

    def test_event_ledger_stores_only_sanitized_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            core = PersistentCore(tmp)
            core.record_event(
                "participant_api_response_received",
                {"response": "private answer", "provider": "openai", "model": "gpt-test"},
            )
            with sqlite3.connect(core.db_path) as db:
                stored = json.loads(db.execute("SELECT data_json FROM events").fetchone()[0])
            self.assertEqual(stored["response_length"], len("private answer"))
            self.assertNotIn("response", stored)
            self.assertEqual(stored["provider"], "openai")

    def test_startup_migration_scrubs_legacy_event_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "yj64-persistent-core.sqlite3"
            with sqlite3.connect(db_path) as db:
                db.execute(
                    "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp_ms INTEGER NOT NULL, event TEXT NOT NULL, data_json TEXT NOT NULL)"
                )
                db.execute(
                    "INSERT INTO events(timestamp_ms,event,data_json) VALUES(1,?,?)",
                    ("participant_request_started", json.dumps({"prompt": "legacy private text"})),
                )
            core = PersistentCore(tmp)
            with sqlite3.connect(core.db_path) as db:
                stored = json.loads(db.execute("SELECT data_json FROM events").fetchone()[0])
            self.assertEqual(stored["prompt_length"], len("legacy private text"))
            self.assertNotIn("prompt", stored)

    def test_common_archive_excludes_report_jsonl_and_private_histories(self):
        with tempfile.TemporaryDirectory() as tmp:
            core = PersistentCore(tmp)
            private_dir = core.workspace_path / "histories"
            common_dir = core.workspace_path / "chats"
            private_dir.mkdir(parents=True)
            common_dir.mkdir(parents=True)
            (private_dir / "Participant 1.json").write_text(
                json.dumps([{"role": "user", "content": "private chat text"}]),
                encoding="utf-8",
            )
            (common_dir / "common.json").write_text(
                json.dumps([{"role": "user", "content": "common chat text"}]),
                encoding="utf-8",
            )
            core.report_path.parent.mkdir(parents=True, exist_ok=True)
            core.report_path.write_text(
                '{"event":"participant_request_started","data":{"prompt":"legacy private prompt"}}\n',
                encoding="utf-8",
            )
            collected = core._collect_files()
            self.assertIn("yj64-workspace/chats/common.json", collected)
            self.assertNotIn("yj64-workspace/histories/Participant 1.json", collected)
            self.assertFalse(any(name.endswith(".jsonl") for name in collected))

    def test_private_bundle_round_trip_restores_private_histories_and_agent_messages(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = PersistentCore(Path(tmp) / "source")
            histories = source.workspace_path / "histories"
            agents = source.workspace_path / "agents"
            histories.mkdir(parents=True)
            agents.mkdir(parents=True)
            history = [{"role": "user", "content": "secret participant message"}]
            private_messages = [{"role": "assistant", "content": "private agent response"}]
            (histories / "participant_1.json").write_text(json.dumps(history), encoding="utf-8")
            (agents / "agent_1.json").write_text(json.dumps({
                "id": "agent_1", "name": "Agent One", "runner": "participant_1",
                "created_ms": 123, "private_messages": private_messages,
            }), encoding="utf-8")
            bundle = Path(tmp) / "private-bundle.zip"
            source.export_private_bundle(bundle)
            self.assertTrue(bundle.is_file())
            target = PersistentCore(Path(tmp) / "target")
            restored = target.import_private_bundle(bundle)
            self.assertEqual(restored, 2)
            self.assertEqual(
                json.loads((target.workspace_path / "histories" / "participant_1.json").read_text(encoding="utf-8")),
                history,
            )
            restored_agent = json.loads((target.workspace_path / "agents" / "agent_1.json").read_text(encoding="utf-8"))
            self.assertEqual(restored_agent["private_messages"], private_messages)

    def test_private_bundle_rejects_tampered_member_without_restoring(self):
        import zipfile
        with tempfile.TemporaryDirectory() as tmp:
            source = PersistentCore(Path(tmp) / "source")
            histories = source.workspace_path / "histories"
            histories.mkdir(parents=True)
            (histories / "participant_1.json").write_text(
                json.dumps([{"role": "user", "content": "private"}]), encoding="utf-8"
            )
            bundle = Path(tmp) / "private-bundle.zip"
            source.export_private_bundle(bundle)
            tampered = Path(tmp) / "tampered.zip"
            with zipfile.ZipFile(bundle, "r") as original, zipfile.ZipFile(tampered, "w") as changed:
                for name in original.namelist():
                    data = original.read(name)
                    if name.startswith("participants/"):
                        data += b"tampered"
                    changed.writestr(name, data)
            target = PersistentCore(Path(tmp) / "target")
            with self.assertRaises(ValueError):
                target.import_private_bundle(tampered)
            self.assertFalse((target.workspace_path / "histories" / "participant_1.json").exists())


if __name__ == "__main__":
    unittest.main()
