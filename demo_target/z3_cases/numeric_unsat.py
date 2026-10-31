"""ST-1: only ASCII digits can reach an unquoted SQL value; no SQL is executed."""

import re

from flask import request


def numeric_lookup():
    order_id = request.args.get("id", "")
    if not re.fullmatch(r"^[0-9]{1,8}$", order_id):
        return None
    return "SELECT id FROM orders WHERE id = " + order_id
