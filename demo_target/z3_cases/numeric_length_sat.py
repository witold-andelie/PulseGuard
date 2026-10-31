"""ST-1: a length limit alone admits unquoted SQL syntax; no SQL is executed."""

from flask import request


def numeric_length_lookup():
    order_id = request.args.get("id", "")
    if len(order_id) > 8:
        return None
    return "SELECT id FROM orders WHERE id = " + order_id
