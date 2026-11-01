function order(req, db) {
    const owner = req.body.owner;
    return db.all("SELECT * FROM orders WHERE owner = ?", [owner]);
}
