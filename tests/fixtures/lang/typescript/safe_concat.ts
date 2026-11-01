function order(req: Request, db: Database) {
    const id: string = req.params.id; // @safe bound value
    return db.query("SELECT * FROM orders WHERE id = $1", [id]);
}
