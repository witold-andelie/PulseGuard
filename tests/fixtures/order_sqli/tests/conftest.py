"""SYNTHETIC fixture tests for PulseGuard scenario 1."""

import sqlite3

import pytest

import routes


@pytest.fixture()
def client(tmp_path):
    db = tmp_path / "orders.sqlite"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE orders (id INTEGER PRIMARY KEY, item TEXT NOT NULL, qty INTEGER NOT NULL);
        INSERT INTO orders (id, item, qty) VALUES (1, 'bond-future', 10), (2, 'swap', 3);
        """
    )
    conn.commit()
    conn.close()
    routes.app.config.update(TESTING=True, DATABASE=str(db))
    with routes.app.test_client() as c:
        yield c
