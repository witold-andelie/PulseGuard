#include <string>
#include <cstring>
#include <sys/socket.h>
#include <oci.h>

int order(OCIStmt *stmt, OCIError *error, int fd) {
    char input[128] = {};
    recv(fd, input, sizeof(input) - 1, 0);
    char query[512] = "SELECT * FROM orders WHERE id = ";
    std::strncat(query, input, sizeof(input) - 1);
    return OCIStmtPrepare(stmt, error, (const OraText *)query, std::strlen(query),
                          OCI_NTV_SYNTAX, OCI_DEFAULT);
}
