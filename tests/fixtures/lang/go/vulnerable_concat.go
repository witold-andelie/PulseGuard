package orders

import "net/http"
import "database/sql"

func order(r *http.Request, db *sql.DB) {
    id := r.URL.Query().Get("id") // @vuln SQL injection
    query := "SELECT * FROM orders WHERE id = '" + id + "'"
    db.Query(query)
}
