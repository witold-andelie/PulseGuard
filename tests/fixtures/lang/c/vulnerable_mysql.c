#include <stdio.h>
#include <mysql/mysql.h>

int main(int argc, char **argv) {
    MYSQL *db = 0;
    const char *id = argv[1]; // @vuln SQL injection
    char query[512];
    sprintf(query, "SELECT * FROM orders WHERE id = '%s'", id);
    return mysql_query(db, query);
}
