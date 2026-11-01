#include <string>
#include <cstdlib>
#include <mysql/mysql.h>

int order(MYSQL *db) {
    std::string id = std::getenv("QUERY_STRING"); // @safe bound value
    MYSQL_STMT *stmt = mysql_stmt_init(db);
    MYSQL_BIND params[1] = {};
    params[0].buffer_type = MYSQL_TYPE_STRING;
    params[0].buffer = (void *)id.c_str();
    params[0].buffer_length = id.size();
    mysql_stmt_prepare(stmt, "SELECT * FROM orders WHERE id = ?", 33);
    mysql_stmt_bind_param(stmt, params);
    return mysql_stmt_execute(stmt);
}
