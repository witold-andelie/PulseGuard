function order(req, db) {
    const id = req.query.id; // @vuln SQL injection
    const query = "SELECT * FROM orders WHERE id = '" + id + "'";
    return db.query(query);
}
