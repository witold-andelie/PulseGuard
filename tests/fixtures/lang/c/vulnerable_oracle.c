#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <oci.h>

int order(OCIStmt *stmt, OCIError *error, int fd) {
    char input[128] = {0};
    recvfrom(fd, input, sizeof(input) - 1, 0, 0, 0);
    char query[512];
    snprintf(query, sizeof(query), "SELECT * FROM orders WHERE id = '%s'", input);
    return OCIStmtPrepare(stmt, error, (const OraText *)query, strlen(query),
                          OCI_NTV_SYNTAX, OCI_DEFAULT);
}
