import flask


def order(conn):
    order_id = flask.request.args.get("id")  # @safe bound value
    return conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchall()
