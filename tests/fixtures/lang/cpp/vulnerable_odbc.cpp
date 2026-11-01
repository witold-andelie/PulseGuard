#include <string>
#include <iostream>
#include <sstream>
#include <sql.h>

int order(SQLHSTMT stmt) {
    std::string prefix, id;
    std::cin >> prefix >> id;
    std::ostringstream query;
    query << "SELECT * FROM orders WHERE id = " << id;
    return SQLExecDirect(stmt, (SQLCHAR *)query.str().c_str(), SQL_NTS);
}
