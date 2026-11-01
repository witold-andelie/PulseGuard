package orders

import "net/http"
import "database/sql"
import "github.com/gorilla/mux"

func order(r *http.Request, db *sql.DB) {
    id := mux.Vars(r)["id"]
    db.QueryContext(r.Context(), "SELECT * FROM orders WHERE id = $1", id)
}
