#include <string.h>
#include <sys/socket.h>
#include <sqlite3.h>

int order(sqlite3 *db, int fd) {
    char input[128] = {0};
    recv(fd, input, sizeof(input) - 1, 0);
    char query[512] = "SELECT * FROM orders WHERE id = ";
    strcat(query, input);
    return sqlite3_exec(db, query, 0, 0, 0);
}
