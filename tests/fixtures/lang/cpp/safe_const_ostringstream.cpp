#include <sstream>
#include <sqlite3.h>

int count_orders(sqlite3 *db) {
    std::ostringstream query;
    query << "SELECT COUNT(*) FROM orders WHERE status = 'OPEN'";
    return sqlite3_exec(db, query.str().c_str(), 0, 0, 0); // @safe constant stream
}
