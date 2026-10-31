"""SYNTHETIC fixture for PulseGuard scenario 1. Not scanner output."""

import os
import sqlite3

from flask import Flask, g, jsonify, request

app = Flask(__name__)
app.config["DATABASE"] = os.environ.get("ORDER_API_DB", "orders.sqlite")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.route("/order")
def order():
    order_id = request.args.get("id")
    if order_id is None:
        return jsonify({"error": "missing id"}), 400
    q = "SELECT id, item, qty FROM orders WHERE id = '" + order_id + "'"
    conn = get_db()
    rows = conn.execute(q).fetchall()  # @vuln sqli
    return jsonify([dict(r) for r in rows])
