package orders

import "net/http"
import "database/sql"

func update(r *http.Request, db *sql.DB) {
    owner := r.FormValue("owner")
    db.Exec("DELETE FROM orders WHERE owner = $1", owner)
}
