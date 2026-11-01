#include <string>
#include <iostream>
#include <libpq-fe.h>

PGresult *order(PGconn *db) {
    std::string id;
    std::getline(std::cin, id);
    const char *values[] = {id.c_str()};
    return PQexecParams(db, "SELECT * FROM orders WHERE id = $1", 1, 0, values, 0, 0, 0);
}
