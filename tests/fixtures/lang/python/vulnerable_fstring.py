import flask


def order(conn):
    order_id = flask.request.args.get("id")
    return conn.execute(f"SELECT * FROM orders WHERE id = {order_id}").fetchall()
