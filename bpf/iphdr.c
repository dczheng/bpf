#include "bpf.h"
#include "config.h"

int
main(void) {
    struct addr_pair_t addr;
    int sock = -1, map = -1, prog = -1, ret = 0, t;
    struct __packed {
        struct ethhdr eth;
        union __packed {
            struct iphdr ipv4;
            struct ipv6hdr ipv6;
        };
    } hdr;

    bpf_init();
    TRY(!(ret = bpf_map_create(&map, BPF_MAP_TYPE_QUEUE, 0,
        sizeof(hdr), MB)), goto err);

    struct bpf_insn insns[] = {
        bpf_mov8(bpf_r9, bpf_r1),

        bpf_skb_load(-2, eth_proto_off, 2, -1),
        bpf_ld2(bpf_r8, bpf_fp, -2),
        bpf_be2(bpf_r8),
        bpf_jeq8i(bpf_r8, ETH_P_IP, 3),
        bpf_jeq8i(bpf_r8, ETH_P_IPV6, 2),
        bpf_return(-1),

        bpf_jeq8i(bpf_r8, ETH_P_IPV6, 6),
        bpf_stack_zero8((sizeof(hdr) - ETH_HLEN - sizeof(hdr.ipv4)) / 8 + 1),

        bpf_mov8(bpf_r1, bpf_r9),
        bpf_mov8i(bpf_r2, 0),
        bpf_mov8(bpf_r3, bpf_fp),
        bpf_add8i(bpf_r3, -sizeof(hdr)),
        bpf_mov8i(bpf_r4, ETH_HLEN + sizeof(hdr.ipv4)),
        bpf_jeq8i(bpf_r8, ETH_P_IP, 1),
        bpf_mov8i(bpf_r4, ETH_HLEN + sizeof(hdr.ipv6)),
        bpf_ret_call(skb_load_bytes, 0, -1),

        bpf_map_push(map, -sizeof(hdr), -1),
        bpf_return(-1),
    };

    bpf_print(insns, LEN(insns));

    TRY(!(ret = bpf_prog_load(&prog, BPF_PROG_TYPE_SOCKET_FILTER, insns,
        LEN(insns), "MIT", 10 * MB)), goto err);

    TRY(!(ret = if_attach(&sock, IFACE, prog)), goto err);

    while (bpf_is_running()) {
        TINYSLEEP();

        ret = bpf_map_pop(map, &hdr);
        if (ret == ENOENT) {
            ret = 0;
            continue;
        }
        TRY(!ret, goto err);

        t = ntohs(hdr.eth.h_proto);
        ASSERT(t == ETH_P_IP || t == ETH_P_IPV6);

        addr_pair(&addr, t == ETH_P_IP ? AF_INET : AF_INET6,
            t == ETH_P_IP ? (void*)&hdr.ipv4 : (void*)&hdr.ipv6);

        LOG("%5s %5s %5d %5d %15s > %-15s\n",
            eth_proto_name(hdr.eth.h_proto),
            t == ETH_P_IP ? ip_proto_name(hdr.ipv4.protocol) : "",
            ntohs(t == ETH_P_IP ? hdr.ipv4.tot_len : hdr.ipv6.payload_len),
            t == ETH_P_IP ? ntohs(hdr.ipv4.id) : -1,
            addr.src, addr.dst);
    }

err:
    if (sock > 0) close(sock);
    if (map > 0) close(map);
    if (prog > 0) close(prog);
    if (ret) LOGERR("%s\n", strerror(ret));
    return ret;
}
