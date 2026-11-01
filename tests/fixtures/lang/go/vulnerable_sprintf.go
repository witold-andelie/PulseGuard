package orders

import "fmt"
import "net/http"
import "database/sql"

func update(r *http.Request, db *sql.DB) {
    owner := r.FormValue("owner")
    query := fmt.Sprintf("DELETE FROM orders WHERE owner = '%s'", owner)
    db.Exec(query)
}
