import flask


def order(conn):
    order_id = flask.request.args.get("id")  # @vuln SQL injection
    query = "SELECT * FROM orders WHERE id = '" + order_id + "'"
    return conn.execute(query).fetchall()
