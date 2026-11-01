#include <string>
#include <cstdlib>
#include <mysql/mysql.h>

int order(MYSQL *db) {
    const char *id = std::getenv("QUERY_STRING"); // @vuln SQL injection
    std::string query = std::string("SELECT * FROM orders WHERE id = '") + id + "'";
    return mysql_query(db, query.c_str());
}
