#include <stdio.h>
#include <string.h>
#include <sql.h>

int order(SQLHSTMT stmt) {
    char input[128] = {0};
    fgets(input, sizeof(input), stdin);
    char query[512] = "SELECT * FROM orders WHERE id = ";
    strncat(query, input, sizeof(input) - 1);
    return SQLExecDirect(stmt, (SQLCHAR *)query, SQL_NTS);
}
