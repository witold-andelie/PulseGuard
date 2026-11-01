#include <sys/socket.h>
#include <oci.h>

int order(OCIStmt *stmt, OCIError *error, OCISvcCtx *service, int fd) {
    char input[128] = {0};
    recvfrom(fd, input, sizeof(input) - 1, 0, 0, 0);
    OCIBind *binding = 0;
    OCIStmtPrepare(stmt, error, (const OraText *)"SELECT * FROM orders WHERE id = :id",
                   35, OCI_NTV_SYNTAX, OCI_DEFAULT);
    OCIBindByName(stmt, &binding, error, (const OraText *)":id", -1, input,
                  sizeof(input), SQLT_STR, 0, 0, 0, 0, 0, OCI_DEFAULT);
    return OCIStmtExecute(service, stmt, error, 0, 0, 0, 0, OCI_DEFAULT);
}
