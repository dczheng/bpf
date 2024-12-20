#ifndef __TOOLS_H__
#define __TOOLS_H__

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>

#include "./tools-common.h"

#define ZEROS(x, n) bzero(x, n)
#define ZERO(x) ZEROS(&(x), sizeof(x))
#define __fallthrough __attribute__((fallthrough))
#define __packed      __attribute__((packed))
#define __unused      __attribute__((unused))

#define LOG(fmt, arg...) printf(fmt, ##arg);
#define _LOGERR(tag, fmt, arg...) do { \
    printf("\033[38;5;1m"); \
    printf("[%s %d] [%s] " fmt, __FILE__, __LINE__, tag, ##arg); \
    printf("\033[38;5;15m"); \
} while(0)

#define LOGERR(fmt, arg...) _LOGERR("ERROR", fmt, ##arg)
#define DIE(fmt, arg...) do { \
    _LOGERR("DIE", fmt, ##arg); \
    _exit(1); \
} while(0)
#define _TRYF(exp, tag, next, fmt, arg...) ({ \
    if (!(exp)) { \
        _LOGERR(tag, "`%s`" fmt, #exp, ##arg); \
        next; \
    } \
    1; \
})

#define TRYF(exp, next, fmt, arg...) \
    _TRYF(exp, "TRY", next, fmt, ##arg)
#define TRY(exp, next) TRYF(exp, next, "\n")
#define ASSERTF(exp, fmt, arg...) \
    _TRYF(exp, "ASSERT", _exit(1), fmt,  ##arg)
#define ASSERT(exp) ASSERTF(exp, "\n")

#define SECOND              1000000000L
#define MILLISECOND         1000000L
#define MICROSECOND         1000L
#define MINUTE              (60 * SECOND)
#define HOUR                (60 * MINUTE)
#define TO_SECOND(t)        (((double)(t)) / SECOND)
#define TO_MILLISECOND(t)   (((double)(t)) / MILLISECOND)
#define TO_MICROSECOND(t)   (((double)(t)) / MICROSECOND)
#define TINYSLEEP() ({ \
    usleep(10000); \
    10000000; \
})
#define SLEEP(t) do { \
    long _t = (t); \
    if (_t > 0) usleep(TO_MICROSECOND(_t)); \
} while(0)
static inline long
get_time(void) {
    struct timespec ts;
    ASSERT(!clock_gettime(CLOCK_MONOTONIC, &ts));
    return ts.tv_sec * SECOND + ts.tv_nsec;
}

#endif
