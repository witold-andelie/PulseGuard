function order(req, db) {
    const id = req.query.id; // @safe bound value
    return db.query("SELECT * FROM orders WHERE id = ?", [id]);
}
