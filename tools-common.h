#ifndef __TOOLS_COMMON_H__
#define __TOOLS_COMMON_H__

#define KB 1024
#define MB (KB * KB)
#define GB (KB * MB)

#define LEN(x) (int)(sizeof(x) / sizeof((x)[0]))

#define RETURN(_ret, _pos) do { \
    ret = _ret; \
    goto _pos; \
} while (0)

#define HEXSTR(v) ({ \
    static char _buf[64]; \
    unsigned long long _v = v; \
    switch (sizeof(v)) { \
    case 1: sprintf(_buf, "0x%02llx", _v); break; \
    case 2: sprintf(_buf, "0x%04llx", _v); break; \
    case 4: sprintf(_buf, "0x%08llx", _v); break; \
    case 8: sprintf(_buf, "0x%016llx", _v); break; \
    default: sprintf(_buf, "0x???"); \
    } \
    _buf; \
})

#endif
