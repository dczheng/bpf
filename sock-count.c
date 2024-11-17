#include <stdio.h>
#include <errno.h>
#include <stddef.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "bpf.h"

char log_buf[1024];

int
main(int argc, char **argv) {
    char *name;
    int sock = -1, map = -1, prog = -1, i, j, ret = 0;
    uint32_t key;
    uint64_t value;
    struct sockaddr_ll addr;

    ASSERT(argc >= 2);
    name = argv[1];
    printf("interface: %s\n", name);

    TRY((map = bpf_map_create(BPF_MAP_TYPE_ARRAY,
        sizeof(key), sizeof(value), IPPROTO_MAX)) != -1,
        goto err);

    struct bpf_insn insns[] = {
        bpf_mov64i(bpf_r2, ETH_HLEN + offsetof(struct iphdr, protocol)),
        bpf_mov64(bpf_r3, bpf_r10),
        bpf_add64i(bpf_r3, -4),
        bpf_mst32i(bpf_r3, 0, 0),
        bpf_mov64i(bpf_r4, 1),
        bpf_call(BPF_FUNC_skb_load_bytes),

        bpf_jne64i(bpf_r0, 0, 8),
        bpf_mov64(bpf_r2, bpf_r10),
        bpf_add64i(bpf_r2, -4),

        bpf_load_fd(bpf_r1, map),
        bpf_call(BPF_FUNC_map_lookup_elem),
        bpf_jeq64i(bpf_r0, 0, 2),
        bpf_mov64i(bpf_r1, 1),
        bpf_atomic_add64(bpf_r0, 0, bpf_r1),

        bpf_mov64i(bpf_r0, 0),
        bpf_exit(),
    };

    bpf_prog_dump(insns, sizeof(insns));

    TRYF((prog = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, insns,
        LEN(insns), 1, log_buf, sizeof(log_buf))) != -1,
        goto err, "%s %s\n", strerror(errno), log_buf);

    TRYF((sock = socket(PF_PACKET,
        SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL))) > 0,
        goto err, "%s\n", strerror(errno));

    ZERO(addr);
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = if_nametoindex(name);
    addr.sll_protocol = htons(ETH_P_ALL);

    TRYF(!bind(sock, (struct sockaddr *)&addr, sizeof(addr)),
        goto err, "%s: %s\n", name, strerror(errno));
    TRYF(!setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog, sizeof(prog)),
        goto err, " %s\n", strerror(errno));

    for (i = 0; i < 10; i++) {
        for (j = 0; j < IPPROTO_MAX; j++) {
            switch(j){
#define _case(t) case IPPROTO_##t: \
                    key = j; \
                    TRYF(bpf_map_lookup(map, &key, &value) != -1, \
                         goto err, " %s\n", strerror(errno)); \
                    printf("%4s: %3lu ", #t, value); \
                    break;
            _case(TCP);
            _case(UDP);
            _case(ICMP);
#undef _case
            }
        }
        printf("\n");
        sleep(1);
    }

err:
    if (sock > 0) close(sock);
    if (map > 0) close(map);
    if (prog > 0) close(prog);
    return ret;
}
