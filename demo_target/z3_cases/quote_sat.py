"""ST-1 labelled case: class including quote and space admits ``'`` (sat).

Scanner input only; the demo app never imports or registers this module.
"""

import re

from flask import request


def quote_class_lookup():
    order_id = request.args.get("id", "")
    if not re.fullmatch(r"^[A-Za-z0-9_\-' ]{1,32}$", order_id):
        return None
    return order_id
