#include <string>
#include <iostream>
#include <sqlite3.h>

int order(sqlite3 *db) {
    std::string id;
    std::cin >> id;
    sqlite3_stmt *stmt = 0;
    sqlite3_prepare_v2(db, "SELECT * FROM orders WHERE id = ?", -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    return sqlite3_step(stmt);
}
