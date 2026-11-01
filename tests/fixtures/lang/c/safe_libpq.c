#include <stdlib.h>
#include <libpq-fe.h>

PGresult *order(PGconn *db) {
    const char *id = getenv("QUERY_STRING");
    const char *values[] = {id};
    return PQexecParams(db, "SELECT * FROM orders WHERE id = $1", 1, 0, values, 0, 0, 0);
}
