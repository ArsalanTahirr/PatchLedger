"""Tests for Bronze CSV ingestion failure handling."""

import csv
import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ingest_bronze.py"


class CaptureStream(io.StringIO):
    pass


def load_ingester():
    spec = importlib.util.spec_from_file_location("ingest_bronze", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_malformed_csv_terminates_uncommitted_import(tmp_path, monkeypatch):
    ingester = load_ingester()

    csv_path = tmp_path / "epss_scores.csv"

    with csv_path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["cve", "epss", "percentile"])
        writer.writerow(["CVE-2026-90001", "0.1", "0.5"])
        writer.writerow(["CVE-2026-90002", "0.2"])

    stream = CaptureStream()

    process = SimpleNamespace(
        stdin=stream,
        stdout=None,
        stderr=io.StringIO(),
        kill=Mock(),
        wait=Mock(return_value=-9),
    )

    def fake_run(*args, **kwargs):
        return SimpleNamespace(stdout="", returncode=0)

    monkeypatch.setattr(
        ingester,
        "subprocess",
        SimpleNamespace(
            run=fake_run,
            Popen=lambda *args, **kwargs: process,
            PIPE=-1,
            DEVNULL=-3,
        ),
    )

    with pytest.raises(ValueError, match="Malformed CSV"):
        ingester.ingest("epss", tmp_path, limit=None)

    process.kill.assert_called_once()
    process.wait.assert_called_once()

    assert "BEGIN;" in stream.getvalue()
    assert "COPY bronze.epss_scores" in stream.getvalue()
    assert "COMMIT;" not in stream.getvalue()
