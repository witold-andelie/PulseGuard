#include <stdio.h>
#include <mysql/mysql.h>

int count_orders(MYSQL *conn) {
    char query[128];
    snprintf(query, sizeof query, "SELECT COUNT(*) FROM orders WHERE status = '%s'", "OPEN");
    return mysql_query(conn, query); // @safe constant format argument
}
