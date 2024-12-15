#include "bpf.h"
#include "config.h"

int
main(int argc, char **argv) {
    char *name = DEFAULT_IFACE;
    int sock = -1, map = -1, prog = -1, i, j, ret = 0,
        proto_off, len_off;
    uint32_t key;
    struct {
        uint64_t count, bytes;
    } stat;

    if (argc > 1) name = argv[1];
    LOG("interface: %s\n", name);

    TRY(!(ret = bpf_map_create(&map, BPF_MAP_TYPE_ARRAY,
        sizeof(key), sizeof(stat), IPPROTO_MAX)), goto err);

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
        bpf_call(BPF_FUNC_map_lookup_elem),
        bpf_jne8i(bpf_r0, 0, 2),
        bpf_return(0),

        bpf_mov8i(bpf_r1, 1),
        bpf_atom_add8(bpf_r0, 0, bpf_r1),
        bpf_ld4(bpf_r1, bpf_fp, -12),
        bpf_atom_add8(bpf_r0, 8, bpf_r1),
        bpf_return(0),
    };

    bpf_prog_print(insns, LEN(insns));

    TRY(!(ret = bpf_prog_load(&prog, BPF_PROG_TYPE_SOCKET_FILTER, insns,
        LEN(insns), "MIT", MB)), goto err);

    TRY(!(ret = if_attach(&sock, name, prog)), goto err);

    for (i = 0; i < 10; i++) {
        for (j = 0; j < IPPROTO_MAX; j++) {
            switch(j){
#define _case(t) \
        case IPPROTO_##t: \
            key = j; \
            TRY(!(ret = bpf_map_lookup(map, &key, &stat)), goto err); \
            LOG("%4s: %3lu/%-8lu ", #t, stat.count, stat.bytes); \
            break;

            _case(TCP);
            _case(UDP);
            _case(ICMP);
#undef _case
            }
        }
        LOG("\n");
        sleep(1);
    }

err:
    if (sock > 0) close(sock);
    if (map > 0) close(map);
    if (prog > 0) close(prog);
    if (ret) LOGERR("%s\n", strerror(ret));
    return ret;
}
