"""ST-1 labelled case: ``^[A-Za-z0-9_-]{1,12}$`` cannot admit a quote (unsat).

Scanner input only; the demo app never imports or registers this module.
"""

import re

from flask import request


def alnum_lookup():
    order_id = request.args.get("id", "")
    if not re.fullmatch(r"^[A-Za-z0-9_-]{1,12}$", order_id):
        return None
    return "SELECT id FROM orders WHERE id = '" + order_id + "'"
