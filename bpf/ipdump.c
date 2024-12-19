#include <linux/tcp.h>
#include <linux/udp.h>

#include "bpf.h"
#include "config.h"
#include "../tools.h"

struct cpu_t {
    union {
        struct __packed {
            struct ethhdr eth;
            struct iphdr ip;
            union __packed {
                struct tcphdr tcp;
                struct udphdr udp;
            };
        };
        char data[65535];
    };
    int size;
} cpu[NCPU] = {0};

int pcap = -1, idx = 0;

void
pkt_save(struct cpu_t *c) {
    int len = ntohs(c->ip.tot_len) + ETH_HLEN;
    char dst[INET6_ADDRSTRLEN], src[INET6_ADDRSTRLEN],
        dst_port[INET6_ADDRSTRLEN+8], src_port[INET6_ADDRSTRLEN+8];

    if (len != c->size) {
        LOGERR("Invalid packet size: %d/%d\n", len, c->size);
        return;
    }

    eth_ip_addr(dst, src, &c->eth);
    if (c->ip.protocol == IPPROTO_TCP || c->ip.protocol == IPPROTO_UDP) {
        snprintf(src_port, sizeof(src_port), "%s:%d",
            src, ntohs(c->udp.source));
        snprintf(dst_port, sizeof(dst_port), "%s:%d",
            dst, ntohs(c->udp.dest));
    } else {
        snprintf(src_port, sizeof(src_port), "%s", src);
        snprintf(dst_port, sizeof(dst_port), "%s", dst);
    }

    LOG("[%05d/%02d] %5s %5d %5d %21s > %-21s\n", idx, (int)(c-cpu),
        ip_proto_name(c->ip.protocol),
        len, ntohs(c->ip.id), src_port, dst_port);
    TRY(!pcap_write(pcap, c->data, c->size),);
    idx++;
}

int
main(void) {
    int sock = -1, map = -1, prog = -1, ret = 0;
    struct __packed {
        uint8_t data[500];
        uint32_t head, size, cpu;
    } pkt;
    struct cpu_t *c;

    bpf_init();
    TRY(!(ret = bpf_map_create(&map, BPF_MAP_TYPE_QUEUE, 0,
        sizeof(pkt), MB)), goto err);

    TRY(!(ret = pcap_open(&pcap, "ipdump.pcap")), goto err);

    struct bpf_insn insns[] = {
        bpf_mov8(bpf_r9, bpf_r1),
        bpf_stack_zero8(64),

        bpf_skb_load(-2, eth_proto_off, 2, -1),
        bpf_ld2(bpf_r1, bpf_fp, -2),
        bpf_be2(bpf_r1),
        bpf_jeq8i(bpf_r1, ETH_P_IP, 2),
        bpf_return(-1),

        bpf_call(get_smp_processor_id),
        bpf_mov8(bpf_r6, bpf_r0),

        bpf_skb_load(-2, ip_len_off, 2, -1),
        bpf_ld2(bpf_r8, bpf_fp, -2),
        bpf_be2(bpf_r8),
        bpf_add8i(bpf_r8, ETH_HLEN),
        bpf_jslt8i(bpf_r8, 65535, 2),
        bpf_return(-1),

        bpf_mov8i(bpf_r7, 0),
        bpf_st4(bpf_fp, -4, bpf_r6),
        bpf_st4i(bpf_fp, -8, sizeof(pkt.data)),
        bpf_st4i(bpf_fp, -12, 1),

        bpf_jslt8i(bpf_r8, sizeof(pkt.data), 22),
        bpf_mov8(bpf_r1, bpf_r9),
        bpf_mov8(bpf_r2, bpf_r7),
        bpf_mov8(bpf_r3, bpf_fp),
        bpf_add8i(bpf_r3, -sizeof(pkt)),
        bpf_mov8i(bpf_r4, sizeof(pkt.data)),
        bpf_ret_call(skb_load_bytes, 0, -1), // 4 ins
        bpf_map_push(map, -sizeof(pkt), -1), // 9 ins
        bpf_add8i(bpf_r8, -sizeof(pkt.data)),
        bpf_add8i(bpf_r7, sizeof(pkt.data)),
        bpf_st4i(bpf_fp, -12, 0),
        bpf_jsge8i(bpf_r8, sizeof(pkt.data), -22),

        bpf_jsgt8i(bpf_r8, 0, 2),
        bpf_return(-1),

        bpf_st4(bpf_fp, -8, bpf_r8),

        bpf_mov8(bpf_r1, bpf_r9),
        bpf_mov8(bpf_r2, bpf_r7),
        bpf_mov8(bpf_r3, bpf_fp),
        bpf_add8i(bpf_r3, -sizeof(pkt)),
        bpf_mov8(bpf_r4, bpf_r8),
        bpf_ret_call(skb_load_bytes, 0, -1),
        bpf_map_push(map, -sizeof(pkt), -1),
        bpf_return(-1),
    };

    bpf_print(insns, LEN(insns));

    TRY(!(ret = bpf_prog_load(&prog, BPF_PROG_TYPE_SOCKET_FILTER, insns,
        LEN(insns), "MIT", 10 * MB)), goto err);

    TRY(!(ret = if_attach(&sock, IFACE, prog)), goto err);

    while (bpf_is_running()) {
        TINYSLEEP();

        ret = bpf_map_pop(map, &pkt);
        if (ret == ENOENT) {
            ret = 0;
            continue;
        }
        TRY(!ret, goto err);

        TRY(pkt.cpu < NCPU, RETURN(EINVAL, err));
        c = &cpu[pkt.cpu];

        if (pkt.head) {
            if (c->size) pkt_save(c);
            c->size = 0;
        }

        memcpy(c->data + c->size, pkt.data, pkt.size);
        c->size += pkt.size;

    }

err:
    if (pcap > 0) close(pcap);
    if (sock > 0) close(sock);
    if (map > 0) close(map);
    if (prog > 0) close(prog);
    if (ret) LOGERR("%s\n", strerror(ret));
    return ret;
}
