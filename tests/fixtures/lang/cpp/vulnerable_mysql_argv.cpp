#include <string>
#include <cstdio>
#include <cstring>
#include <mysql/mysql.h>

int main(int argc, char **argv) {
    MYSQL *db = 0;
    const char *id = argv[1];
    char query[512];
    std::snprintf(query, sizeof(query), "SELECT * FROM orders WHERE id = '%s'", id);
    return mysql_real_query(db, query, std::strlen(query));
}
