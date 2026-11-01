#include <string>
#include <iostream>
#include <sstream>
#include <sqlite3.h>

int order(sqlite3 *db) {
    std::string id;
    std::cin >> id;
    std::ostringstream query;
    query << "SELECT * FROM orders WHERE id = '" << id << "'";
    return sqlite3_exec(db, query.str().c_str(), 0, 0, 0);
}
