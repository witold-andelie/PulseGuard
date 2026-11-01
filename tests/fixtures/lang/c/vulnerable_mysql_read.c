#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <mysql/mysql.h>

int order(MYSQL *db, int fd) {
    char input[128] = {0};
    read(fd, input, sizeof(input) - 1);
    char query[512];
    snprintf(query, sizeof(query), "SELECT * FROM orders WHERE id = '%s'", input);
    return mysql_real_query(db, query, strlen(query));
}
