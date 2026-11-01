#include <sys/socket.h>
#include <sqlite3.h>

int order(sqlite3 *db, int fd) {
    char input[128] = {0};
    recv(fd, input, sizeof(input) - 1, 0);
    sqlite3_stmt *stmt = 0;
    sqlite3_prepare_v2(db, "SELECT * FROM orders WHERE id = ?", -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, input, -1, SQLITE_TRANSIENT);
    return sqlite3_step(stmt);
}
