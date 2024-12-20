#include <linux/namei.h>
#include <linux/ctype.h>
#include <linux/uprobes.h>

#include "../module.h"

static char *filename;
static long offset;
static struct inode *inode;
static struct uprobe_consumer uc;
static char buf[16*KB];

module_param(filename, charp, S_IRUGO);
module_param(offset, long, S_IRUGO);

static void dump(uint8_t *data, size_t size) {
    size_t p, n;

    for (p = 0; p < size; p += n) {
        n = size - p;
        if (n > sizeof(buf)) n = sizeof(buf);
        TRY(!copy_from_user(buf, data + p, n), return);
        LOG("%s\n", buf);
    }

}

static int handler_pre(struct uprobe_consumer *self, struct pt_regs *regs) {
    dump((uint8_t*)regs->di, regs->si);
    return 0;
}

static int handler_ret(struct uprobe_consumer *self, unsigned long func,
    struct pt_regs *regs) {
    return 0;
}

static int __init uprobe_init(void) {
    struct path path;
    int ret = 0;

    TRY(filename, RETURN(EINVAL, err));

    TRY(!(ret = kern_path(filename, LOOKUP_FOLLOW, &path)), goto err);
    inode = igrab(path.dentry->d_inode);
    path_put(&path);

    uc.handler = handler_pre,
    uc.ret_handler = handler_ret,
    TRY(!(ret = uprobe_register(inode, offset, &uc)), goto err);
    LOG("probe %s %lx\n", filename, offset);

err:
    return ret;
}

static void __exit uprobe_exit(void) {
    uprobe_unregister(inode, offset, &uc);
    LOG("uprobe exit\n");
}

MOD_INIT(uprobe);
