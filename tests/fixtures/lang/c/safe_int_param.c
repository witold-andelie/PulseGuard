#include <stdio.h>
#include <mysql/mysql.h>

int by_number(MYSQL *conn, int id) {
    char query[128];
    snprintf(query, sizeof query, "SELECT * FROM orders WHERE id = %d", id);
    return mysql_query(conn, query); // @safe integer parameter
}
