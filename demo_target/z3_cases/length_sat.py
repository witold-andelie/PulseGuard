"""ST-1 labelled case: length ≤ 8 only admits a quote (sat, e.g. ``' OR 1=1``).

Scanner input only; the demo app never imports or registers this module.
"""

from flask import request


def length_lookup():
    order_id = request.args.get("id", "")
    if len(order_id) > 8:
        return None
    return "SELECT id FROM orders WHERE id = '" + order_id + "'"
