#include <sstream>
#include <mysql/mysql.h>

int by_number(MYSQL *conn, int id) {
    std::ostringstream query;
    query << "SELECT * FROM orders WHERE id = " << id;
    return mysql_query(conn, query.str().c_str()); // @safe integer parameter
}
