#include <string.h>
#include <mysql/mysql.h>

int main(int argc, char **argv) {
    MYSQL *db = 0;
    const char *id = argv[1]; // @safe bound value
    MYSQL_STMT *stmt = mysql_stmt_init(db);
    MYSQL_BIND params[1] = {0};
    params[0].buffer_type = MYSQL_TYPE_STRING;
    params[0].buffer = (void *)id;
    params[0].buffer_length = strlen(id);
    mysql_stmt_prepare(stmt, "SELECT * FROM orders WHERE id = ?", 33);
    mysql_stmt_bind_param(stmt, params);
    return mysql_stmt_execute(stmt);
}
