#include <string>
#include <iostream>
#include <sql.h>
#include <sqlext.h>

int order(SQLHSTMT stmt) {
    std::string prefix, id;
    std::cin >> prefix >> id;
    SQLPrepare(stmt, (SQLCHAR *)"SELECT * FROM orders WHERE id = ?", SQL_NTS);
    SQLBindParameter(stmt, 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR,
                     127, 0, (SQLPOINTER)id.c_str(), id.size() + 1, 0);
    return SQLExecute(stmt);
}
