function order(req: Request, db: Database) {
    const id: string = req.params.id; // @vuln SQL injection
    const query = "SELECT * FROM orders WHERE id = '" + id + "'";
    return db.query(query);
}
