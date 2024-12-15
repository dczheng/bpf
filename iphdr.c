#include "bpf.h"
#include "config.h"

int
main(void) {
    char type[16],
        saddr[INET6_ADDRSTRLEN], daddr[INET6_ADDRSTRLEN];
    int sock = -1, map = -1, prog = -1, ret = 0, t, id, len;
    long tstart;
    struct PACKED {
        struct ethhdr eth;
        union PACKED {
            struct iphdr ipv4;
            struct ipv6hdr ipv6;
        };
    } hdr;

    TRY(!(ret = bpf_map_create(&map, BPF_MAP_TYPE_QUEUE, 0,
        sizeof(hdr), MB)), goto err);

    struct bpf_insn insns[] = {
        bpf_mov8(bpf_r9, bpf_r1),

        bpf_mov8(bpf_r1, bpf_r9),
        bpf_mov8i(bpf_r2, offsetof(struct ethhdr, h_proto)),
        bpf_mov8(bpf_r3, bpf_fp),
        bpf_add8i(bpf_r3, -4),
        bpf_st4i(bpf_r3, 0, 0),
        bpf_mov8i(bpf_r4, 2),
        bpf_call(BPF_FUNC_skb_load_bytes),
        bpf_jeq8i(bpf_r0, 0, 2),
        bpf_return(0),

        bpf_ld4(bpf_r8, bpf_fp, -4),
        bpf_swap2(bpf_r8),
        bpf_jeq8i(bpf_r8, ETH_P_IP, 3),
        bpf_jeq8i(bpf_r8, ETH_P_IPV6, 2),
        bpf_return(0),

        bpf_mov8(bpf_r1, bpf_r9),
        bpf_mov8i(bpf_r2, 0),
        bpf_mov8(bpf_r3, bpf_fp),
        bpf_add8i(bpf_r3, -sizeof(hdr)),
        bpf_mov8i(bpf_r4, ETH_HLEN + sizeof(hdr.ipv4)),
        bpf_jeq8i(bpf_r8, ETH_P_IP, 1),
        bpf_mov8i(bpf_r4, ETH_HLEN + sizeof(hdr.ipv6)),
        bpf_call(BPF_FUNC_skb_load_bytes),
        bpf_jeq8i(bpf_r0, 0, 2),
        bpf_return(0),

        bpf_imm8_map_ld(bpf_r1, map),
        bpf_mov8(bpf_r2, bpf_fp),
        bpf_add8i(bpf_r2, -sizeof(hdr)),
        bpf_mov8i(bpf_r3, BPF_ANY),
        bpf_call(BPF_FUNC_map_push_elem),

        bpf_return(0),
    };

    bpf_prog_print(insns, LEN(insns));

    TRY(!(ret = bpf_prog_load(&prog, BPF_PROG_TYPE_SOCKET_FILTER, insns,
        LEN(insns), "MIT", 10 * MB)), goto err);

    TRY(!(ret = if_attach(&sock, IFACE, prog)), goto err);

    tstart = get_time();
    while (1) {
        TINYSLEEP();
        if (TO_SECOND(get_time() - tstart) > DURATION) {
            ret = 0;
            break;
        }

        ret = bpf_map_pop(map, &hdr);
        if (ret == ENOENT)
            continue;
        TRY(!ret, goto err);

        t = ntohs(hdr.eth.h_proto);
        switch(t) {
        case ETH_P_IP:
            switch (hdr.ipv4.protocol) {
            #define _case(p) case IPPROTO_##p: \
                snprintf(type, sizeof(type), "%s", #p); \
                break;
            _case(IGMP);
            _case(ICMP);
            _case(ICMPV6);
            _case(TCP);
            _case(UDP);
            default: snprintf(type, sizeof(type), "%d", hdr.ipv4.protocol);
            }
            inet_ntop(AF_INET, &hdr.ipv4.saddr, saddr, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &hdr.ipv4.daddr, daddr, INET_ADDRSTRLEN);
            id = ntohs(hdr.ipv4.id);
            len = ntohs(hdr.ipv4.tot_len);
            break;
        case ETH_P_IPV6:
            inet_ntop(AF_INET6, &hdr.ipv6.saddr, saddr, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &hdr.ipv6.daddr, daddr, INET6_ADDRSTRLEN);
            sprintf(type, "IPV6");
            id = -1;
            len = ntohs(hdr.ipv6.payload_len);
            break;
        default: DIE("can't be %x!\n", t);
        }
        LOG("%8s %5d %5d %s > %s\n", type, id, len, saddr, daddr);
    }

err:
    if (sock > 0) close(sock);
    if (map > 0) close(map);
    if (prog > 0) close(prog);
    if (ret) LOGERR("%s\n", strerror(ret));
    return ret;
}
