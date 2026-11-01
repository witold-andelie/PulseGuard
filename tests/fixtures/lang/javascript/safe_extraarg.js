function order(req, db) {
    const id = req.query.id;
    return db.execute("SELECT * FROM orders WHERE id = ? AND owner = ?", [id, "alice"]);
}
