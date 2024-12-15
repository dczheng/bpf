#include "bpf.h"
#include "config.h"

int
main(int argc, char **argv) {
    char *name = DEFAULT_IFACE;
    int sock = -1, map = -1, prog = -1, i, ret = 0,
        proto_off, len_off;
    struct {
        uint32_t proto, bytes;
    } pkt;

    struct {
        uint64_t count, bytes;
    } proto[IPPROTO_MAX];

    if (argc > 1) name = argv[1];
    LOG("interface: %s\n", name);

    ZERO(proto);
    TRY(!(ret = bpf_map_create(&map, BPF_MAP_TYPE_QUEUE, 0,
        sizeof(pkt), MB)), goto err);

    proto_off = ETH_HLEN + offsetof(struct iphdr, protocol);
    len_off = ETH_HLEN + offsetof(struct iphdr, tot_len);

    struct bpf_insn insns[] = {
        bpf_st8(bpf_fp, -8, bpf_r1),

        bpf_ld8(bpf_r1, bpf_fp, -8),
        bpf_mov4i(bpf_r2, len_off),
        bpf_mov8(bpf_r3, bpf_fp),
        bpf_add8i(bpf_r3, -12),
        bpf_st4i(bpf_r3, 0, 0),
        bpf_mov4i(bpf_r4, 2),
        bpf_call(BPF_FUNC_skb_load_bytes),
        bpf_jeq8i(bpf_r0, 0, 2),
        bpf_return(0),

        bpf_ld8(bpf_r1, bpf_fp, -8),
        bpf_mov4i(bpf_r2, proto_off),
        bpf_mov8(bpf_r3, bpf_fp),
        bpf_add8i(bpf_r3, -16),
        bpf_st4i(bpf_r3, 0, 0),
        bpf_mov4i(bpf_r4, 1),
        bpf_call(BPF_FUNC_skb_load_bytes),
        bpf_jeq8i(bpf_r0, 0, 2),
        bpf_return(0),

        bpf_imm8_map_ld(bpf_r1, map),
        bpf_mov8(bpf_r2, bpf_fp),
        bpf_add8i(bpf_r2, -16),
        bpf_mov8i(bpf_r3, BPF_ANY),
        bpf_call(BPF_FUNC_map_push_elem),
        bpf_return(0),
    };

    bpf_prog_print(insns, LEN(insns));

    TRY(!(ret = bpf_prog_load(&prog, BPF_PROG_TYPE_SOCKET_FILTER, insns,
        LEN(insns), "MIT", MB)), goto err);

    TRY(!(ret = if_attach(&sock, name, prog)), goto err);

    for (i = 0; i < 10; i++) {
        while (1) {
            ret = bpf_map_pop(map, &pkt);
            if (ret == ENOENT) {
                ret = 0;
                break;
            }
            TRY(!ret, goto err);
            TRY(pkt.proto < IPPROTO_MAX, RETURN(EINVAL, err));
            proto[pkt.proto].count++;
            proto[pkt.proto].bytes += pkt.bytes;
        }

#define mylog(p) LOG("%4s: %3lu/%-8lu ", #p, proto[IPPROTO_##p].count, \
                    proto[IPPROTO_##p].bytes)
        mylog(ICMP);
        mylog(TCP);
        mylog(UDP);
        LOG("\n");
#undef mylog
        sleep(1);
    }

err:
    if (sock > 0) close(sock);
    if (map > 0) close(map);
    if (prog > 0) close(prog);
    if (ret) LOGERR("%s\n", strerror(ret));
    return ret;
}
