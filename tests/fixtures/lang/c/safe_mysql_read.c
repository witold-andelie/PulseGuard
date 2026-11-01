#include <string.h>
#include <unistd.h>
#include <mysql/mysql.h>

int order(MYSQL *db, int fd) {
    char input[128] = {0};
    read(fd, input, sizeof(input) - 1);
    MYSQL_STMT *stmt = mysql_stmt_init(db);
    MYSQL_BIND params[1] = {0};
    params[0].buffer_type = MYSQL_TYPE_STRING;
    params[0].buffer = input;
    params[0].buffer_length = strlen(input);
    mysql_stmt_prepare(stmt, "SELECT * FROM orders WHERE id = ?", 33);
    mysql_stmt_bind_param(stmt, params);
    return mysql_stmt_execute(stmt);
}
