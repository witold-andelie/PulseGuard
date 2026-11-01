function order(req: Request, db: Database) {
    const owner = req.headers.owner;
    return db.query(`SELECT * FROM orders WHERE owner = '${owner}'`);
}
