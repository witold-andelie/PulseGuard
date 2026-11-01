#include <string>
#include <mysql/mysql.h>

int main(int argc, char **argv) {
    MYSQL *db = 0;
    std::string id = argv[1];
    MYSQL_STMT *stmt = mysql_stmt_init(db);
    MYSQL_BIND params[1] = {};
    params[0].buffer_type = MYSQL_TYPE_STRING;
    params[0].buffer = (void *)id.c_str();
    params[0].buffer_length = id.size();
    mysql_stmt_prepare(stmt, "SELECT * FROM orders WHERE id = ?", 33);
    mysql_stmt_bind_param(stmt, params);
    return mysql_stmt_execute(stmt);
}
