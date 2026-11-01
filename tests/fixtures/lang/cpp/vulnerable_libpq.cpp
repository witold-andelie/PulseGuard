#include <string>
#include <iostream>
#include <libpq-fe.h>

PGresult *order(PGconn *db) {
    std::string id;
    std::getline(std::cin, id);
    std::string query = "SELECT * FROM orders WHERE id = ";
    query.append(id);
    return PQexec(db, query.c_str());
}
