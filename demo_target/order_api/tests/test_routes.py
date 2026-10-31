"""Regression tests for the demo order-api (Flask test client, throwaway SQLite fixture).

These assert behaviour for valid input only, so a correct parameterised-query patch keeps them
green (sandbox gate: pytest must pass after the patch).
"""

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


def test_order_returns_matching_row(client):
    resp = client.get("/order?id=1")
    assert resp.status_code == 200
    assert resp.get_json() == [{"id": 1, "item": "bond-future", "qty": 10}]
    assert client.get("/order_by_number?number=1").get_json() == resp.get_json()
    assert client.get("/order_note?note=bond").get_json() == resp.get_json()


def test_unknown_order_returns_empty_list(client):
    resp = client.get("/order?id=999")
    assert resp.status_code == 200
    assert resp.get_json() == []
    assert client.get("/order_by_number?number=999").get_json() == []
    assert client.get("/order_note?note=missing").get_json() == []
    assert client.get("/order_note?note=' OR '1'='1").get_json() == []


def test_missing_id_is_rejected(client):
    resp = client.get("/order")
    assert resp.status_code == 400
    for query in ("", "?number=no", "?number=1' OR '1'='1"):
        assert client.get("/order_by_number" + query).status_code == 400
