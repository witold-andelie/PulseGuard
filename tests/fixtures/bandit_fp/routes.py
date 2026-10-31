"""SYNTHETIC fixture for PulseGuard scenario 3 (bandit B608 on an int()-cast value)."""


def order_by_number():
    number = int(request.args.get("n"))  # @safe int-cast
    q = "SELECT id, item, qty FROM orders WHERE id = '" + str(number) + "'"
    return conn.execute(q)
