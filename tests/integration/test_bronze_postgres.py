"""Test Bronze imports against disposable PostgreSQL databases."""

import csv
import importlib.util
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import text

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ingest_bronze.py"
SCHEMA = ROOT / "sql/bronze/001_create_tables.sql"


def load_ingester():
    spec = importlib.util.spec_from_file_location("bronze_importer_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def bronze_importer(postgres_engine, monkeypatch):
    database = postgres_engine.url.database

    if not database.startswith("patchledger_test_"):
        pytest.fail("STOP: Refusing to use a non-disposable database")

    with postgres_engine.begin() as conn:
        conn.exec_driver_sql(SCHEMA.read_text())

    ingester = load_ingester()

    original_run = subprocess.run
    original_popen = subprocess.Popen

    url = postgres_engine.url

    if (
        url.drivername != "postgresql+psycopg"
        or url.host not in ("localhost", "127.0.0.1")
        or (url.port or 5432) != 5432
        or not url.username
    ):
        pytest.fail("STOP: Unexpected test PostgreSQL connection")

    connection_env = {
        "PGHOST": url.host,
        "PGPORT": str(url.port or 5432),
        "PGUSER": url.username,
        "PGPASSWORD": url.password or "",
        "PGDATABASE": database,
    }

    def redirect(command):
        command = list(command)

        if command[:5] != ["docker", "exec", "-i", "patchledger-postgres", "psql"]:
            raise RuntimeError("STOP: Unexpected PostgreSQL command")

        position = command.index("-d")

        if command[position + 1] != "patchledger":
            raise RuntimeError("STOP: Unexpected original database")

        return [
            "psql",
            "-h",
            url.host,
            "-p",
            str(url.port or 5432),
            "-U",
            url.username,
            *command[5:position],
            "-d",
            database,
            *command[position + 2 :],
        ]

    def safe_run(command, *args, **kwargs):
        kwargs["env"] = {
            **os.environ,
            **kwargs.get("env", {}),
            **connection_env,
        }
        return original_run(redirect(command), *args, **kwargs)

    def safe_popen(command, *args, **kwargs):
        kwargs["env"] = {
            **os.environ,
            **kwargs.get("env", {}),
            **connection_env,
        }
        return original_popen(redirect(command), *args, **kwargs)

    monkeypatch.setattr(
        ingester,
        "subprocess",
        SimpleNamespace(
            run=safe_run,
            Popen=safe_popen,
            PIPE=subprocess.PIPE,
            DEVNULL=subprocess.DEVNULL,
        ),
    )

    return ingester, postgres_engine


def write_epss(folder, rows):
    path = folder / "epss_scores.csv"

    with path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["cve", "epss", "percentile"])
        writer.writerows(rows)

    return path


def counts(engine):
    with engine.connect() as conn:
        batches = conn.execute(
            text("SELECT COUNT(*) FROM bronze.ingest_batches")
        ).scalar_one()

        rows = conn.execute(
            text("SELECT COUNT(*) FROM bronze.epss_scores")
        ).scalar_one()

    return batches, rows


def test_successful_import(bronze_importer, tmp_path):
    ingester, engine = bronze_importer

    write_epss(
        tmp_path,
        [
            ["CVE-2026-90001", "0.1", "0.5"],
            ["CVE-2026-90002", "0.2", "0.6"],
        ],
    )

    ingester.ingest("epss", tmp_path, limit=None)

    assert counts(engine) == (1, 2)

    # Reimporting the same source must not duplicate data.
    ingester.ingest("epss", tmp_path, limit=None)

    assert counts(engine) == (1, 2)


def test_malformed_csv_rollback(bronze_importer, tmp_path):
    ingester, engine = bronze_importer

    write_epss(
        tmp_path,
        [
            ["CVE-2026-90001", "0.1", "0.5"],
            ["CVE-2026-90002", "0.2"],
        ],
    )

    with pytest.raises(ValueError, match="Malformed CSV"):
        ingester.ingest("epss", tmp_path, limit=None)

    assert counts(engine) == (0, 0)


def test_postgresql_error_reporting(bronze_importer, tmp_path):
    ingester, engine = bronze_importer

    with engine.begin() as conn:
        conn.exec_driver_sql(
            "ALTER TABLE bronze.epss_scores "
            "ADD CONSTRAINT ck_test_epss "
            "CHECK (epss <> 'INVALID')"
        )

    write_epss(
        tmp_path,
        [
            ["CVE-2026-90003", "INVALID", "0.5"],
        ],
    )

    with pytest.raises(RuntimeError, match="PostgreSQL import failed"):
        ingester.ingest("epss", tmp_path, limit=None)

    assert counts(engine) == (0, 0)


def test_simultaneous_imports_are_idempotent(bronze_importer, tmp_path, monkeypatch):
    """Two simultaneous imports must produce only one committed batch."""
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor

    ingester, engine = bronze_importer

    write_epss(
        tmp_path,
        [
            ["CVE-2026-90001", "0.1", "0.5"],
            ["CVE-2026-90002", "0.2", "0.6"],
        ],
    )

    original_run = ingester.subprocess.run

    def delayed_run(*args, **kwargs):
        result = original_run(*args, **kwargs)
        # Widen the race window after the duplicate check.
        time.sleep(0.2)
        return result

    monkeypatch.setattr(ingester.subprocess, "run", delayed_run)

    barrier = threading.Barrier(2)

    def run_import():
        barrier.wait(timeout=10)
        ingester.ingest("epss", tmp_path, limit=None)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(run_import) for _ in range(2)]
        for future in futures:
            future.result(timeout=30)

    assert counts(engine) == (1, 2)
