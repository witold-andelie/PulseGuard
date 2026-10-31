"""ST-1: a conditional guard cannot govern every sink path; no SQL is executed."""

import re

from flask import request


def conditional_lookup():
    order_id = request.args.get("id", "")
    if request.args.get("validate"):
        if not re.fullmatch(r"^[0-9]{1,8}$", order_id):
            return None
    return "SELECT id FROM orders WHERE id = '" + order_id + "'"
