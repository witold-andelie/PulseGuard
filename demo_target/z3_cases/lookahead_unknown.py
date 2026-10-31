"""ST-1 labelled case: lookahead is outside the regex subset (unknown, no claim).

Scanner input only; the demo app never imports or registers this module.
"""

import re

from flask import request


def lookahead_lookup():
    order_id = request.args.get("id", "")
    if not re.fullmatch(r"^(?=.*[A-Z])[A-Za-z0-9]{1,12}$", order_id):
        return None
    return order_id
