#include "../tools.h"

int
func(char *p, size_t n) {
    LOG("[%ld] %s\n", n, p);
    return 0;
}

int
main(void) {
    char buf[128];
    size_t idx;

    for (idx = 0;; idx++) {
        SLEEP(SECOND);
        snprintf(buf, sizeof(buf), "%ld", idx);
        func(buf, strlen(buf));
    }
    return 0;
}
