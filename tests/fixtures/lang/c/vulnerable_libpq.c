#include <stdio.h>
#include <stdlib.h>
#include <libpq-fe.h>

PGresult *order(PGconn *db) {
    const char *id = getenv("QUERY_STRING");
    char query[512];
    snprintf(query, sizeof(query), "SELECT * FROM orders WHERE id = '%s'", id);
    return PQexec(db, query);
}
