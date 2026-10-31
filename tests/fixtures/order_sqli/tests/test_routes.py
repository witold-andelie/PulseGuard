"""SYNTHETIC fixture tests: valid-input behaviour only, so a parameterised patch stays green."""


def test_order_returns_matching_row(client):
    resp = client.get("/order?id=1")
    assert resp.status_code == 200
    assert resp.get_json() == [{"id": 1, "item": "bond-future", "qty": 10}]


def test_unknown_order_returns_empty_list(client):
    resp = client.get("/order?id=999")
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_missing_id_is_rejected(client):
    resp = client.get("/order")
    assert resp.status_code == 400
