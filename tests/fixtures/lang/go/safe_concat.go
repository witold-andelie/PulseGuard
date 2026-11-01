package orders

import "net/http"
import "database/sql"

func order(r *http.Request, db *sql.DB) {
    id := r.URL.Query().Get("id") // @safe bound value
    db.Query("SELECT * FROM orders WHERE id = ?", id)
}
