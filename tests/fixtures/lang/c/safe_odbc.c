#include <stdio.h>
#include <sql.h>
#include <sqlext.h>

int order(SQLHSTMT stmt) {
    char input[128] = {0};
    fgets(input, sizeof(input), stdin);
    SQLPrepare(stmt, (SQLCHAR *)"SELECT * FROM orders WHERE id = ?", SQL_NTS);
    SQLBindParameter(stmt, 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR,
                     127, 0, input, sizeof(input), 0);
    return SQLExecute(stmt);
}
