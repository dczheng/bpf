#ifndef __MODULE_H__
#define __MODULE_H__

#include <linux/module.h>
#include <linux/ptrace.h>

#include "./tools-common.h"

#define MOD_INIT(name) \
    module_init(name##_init); \
    module_exit(name##_exit); \
    MODULE_LICENSE("GPL"); \
    MODULE_AUTHOR("dczheng"); \
    MODULE_VERSION("v0.1"); \
    MODULE_DESCRIPTION(#name);

#define LOG pr_info
#define _TRYF(exp, next, fmt, arg...) ({ \
    if (!(exp)) { \
        pr_err("[%s %d] " fmt, __FILE__, __LINE__, ##arg); \
        next; \
    } \
    1; \
})
#define TRYF(exp, next, fmt, arg...) _TRYF(exp, next, fmt, ##arg)
#define TRY(exp, next) TRYF(exp, next, "\n")

#endif
