#ifndef __BPF_H__
#define __BPF_H__

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#define LEN(x) (int)(sizeof(x) / sizeof((x)[0]))
#define ZEROS(x, n) bzero(x, n)
#define ZERO(x) ZEROS(&(x), sizeof(x))

#define DIE(fmt, ...) do { \
    printf("[%s %d] [DIE] " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
    _exit(1); \
} while(0)

#define _TRYF(exp, tag, next, fmt, ...) ({ \
    if (!(exp)) { \
        printf("\033[38;5;1m"); \
        printf("[%s %d] [%s] `%s` " fmt, __FILE__, __LINE__, \
            tag, #exp, ##__VA_ARGS__); \
        printf("\033[38;5;15m"); \
        next; \
    } \
    1; \
})

#define TRYF(exp, next, fmt, ...) \
    _TRYF(exp, "TRY", next, fmt, ##__VA_ARGS__)
#define TRY(exp, next) TRYF(exp, next, "\n")
#define ASSERTF(exp, fmt, ...) \
    _TRYF(exp, "ASSERT", _exit(1), fmt,  ##__VA_ARGS__)
#define ASSERT(exp) ASSERTF(exp, "\n")

#define RETURN(_ret, _pos) do { \
    ret = _ret; \
    goto _pos; \
} while (0)

#ifndef offsetofend
#define offsetofend(TYPE, MEMBER) \
    (offsetof(TYPE, MEMBER) + sizeof((((TYPE *)0)->MEMBER)))
#endif

#define bpf_r0 BPF_REG_0
#define bpf_r1 BPF_REG_1
#define bpf_r2 BPF_REG_2
#define bpf_r3 BPF_REG_3
#define bpf_r4 BPF_REG_4
#define bpf_r5 BPF_REG_5
#define bpf_r6 BPF_REG_6
#define bpf_r7 BPF_REG_7
#define bpf_r8 BPF_REG_8
#define bpf_r9 BPF_REG_9
#define bpf_r10 BPF_REG_10

#define bpf_cmd(_code, _dst_reg, _src_reg, _off, _imm) \
    ((struct bpf_insn) { \
        .code  = _code, \
        .dst_reg = _dst_reg, \
        .src_reg = _src_reg, \
        .off = _off, \
        .imm   = _imm})

#define bpf_add32(d, s)      bpf_cmd(BPF_ADD |BPF_X|BPF_ALU, d, s, 0, 0)
#define bpf_sub32(d, s)      bpf_cmd(BPF_SUB |BPF_X|BPF_ALU, d, s, 0, 0)
#define bpf_mul32(d, s)      bpf_cmd(BPF_MUL |BPF_X|BPF_ALU, d, s, 0, 0)
#define bpf_div32(d, s)      bpf_cmd(BPF_DIV |BPF_X|BPF_ALU, d, s, 0, 0)
#define bpf_or32(d, s)       bpf_cmd(BPF_OR  |BPF_X|BPF_ALU, d, s, 0, 0)
#define bpf_and32(d, s)      bpf_cmd(BPF_AND |BPF_X|BPF_ALU, d, s, 0, 0)
#define bpf_lsh32(d, s)      bpf_cmd(BPF_LSH |BPF_X|BPF_ALU, d, s, 0, 0)
#define bpf_rsh32(d, s)      bpf_cmd(BPF_RSH |BPF_X|BPF_ALU, d, s, 0, 0)
#define bpf_neg32(d)         bpf_cmd(BPF_NEG |BPF_X|BPF_ALU, d, 0, 0, 0)
#define bpf_mod32(d, s)      bpf_cmd(BPF_MOD |BPF_X|BPF_ALU, d, s, 0, 0)
#define bpf_xor32(d, s)      bpf_cmd(BPF_XOR |BPF_X|BPF_ALU, d, s, 0, 0)
#define bpf_mov32(d, s)      bpf_cmd(BPF_MOV |BPF_X|BPF_ALU, d, s, 0, 0)
#define bpf_arsh32(d, s)     bpf_cmd(BPF_ARSH|BPF_X|BPF_ALU, d, s, 0, 0)
#define bpf_sdiv32(d, s)     bpf_cmd(BPF_DIV |BPF_X|BPF_ALU, d, s, 1, 0)
#define bpf_smod32(d, s)     bpf_cmd(BPF_MOD |BPF_X|BPF_ALU, d, s, 1, 0)
#define bpf_smov8(d, s)      bpf_cmd(BPF_MOV |BPF_X|BPF_ALU, d, s, 8, 0)
#define bpf_smov16(d, s)     bpf_cmd(BPF_MOV |BPF_X|BPF_ALU, d, s, 16, 0)
#define bpf_smov32(d, s)     bpf_cmd(BPF_MOV |BPF_X|BPF_ALU, d, s, 32, 0)

#define bpf_add32i(d, s)     bpf_cmd(BPF_ADD |BPF_K|BPF_ALU, d, 0, 0, s)
#define bpf_sub32i(d, s)     bpf_cmd(BPF_SUB |BPF_K|BPF_ALU, d, 0, 0, s)
#define bpf_mul32i(d, s)     bpf_cmd(BPF_MUL |BPF_K|BPF_ALU, d, 0, 0, s)
#define bpf_div32i(d, s)     bpf_cmd(BPF_DIV |BPF_K|BPF_ALU, d, 0, 0, s)
#define bpf_or32i(d, s)      bpf_cmd(BPF_OR  |BPF_K|BPF_ALU, d, 0, 0, s)
#define bpf_and32i(d, s)     bpf_cmd(BPF_AND |BPF_K|BPF_ALU, d, 0, 0, s)
#define bpf_lsh32i(d, s)     bpf_cmd(BPF_LSH |BPF_K|BPF_ALU, d, 0, 0, s)
#define bpf_rsh32i(d, s)     bpf_cmd(BPF_RSH |BPF_K|BPF_ALU, d, 0, 0, s)
#define bpf_mod32i(d, s)     bpf_cmd(BPF_MOD |BPF_K|BPF_ALU, d, 0, 0, s)
#define bpf_xor32i(d, s)     bpf_cmd(BPF_XOR |BPF_K|BPF_ALU, d, 0, 0, s)
#define bpf_mov32i(d, s)     bpf_cmd(BPF_MOV |BPF_K|BPF_ALU, d, 0, 0, s)
#define bpf_arsh32i(d, s)    bpf_cmd(BPF_ARSH|BPF_K|BPF_ALU, d, 0, 0, s)
#define bpf_smod32i(d, s)    bpf_cmd(BPF_MOD |BPF_K|BPF_ALU, d, 0, 1, s)
#define bpf_sdiv32i(d, s)    bpf_cmd(BPF_DIV |BPF_K|BPF_ALU, d, 0, 1, s)
#define bpf_smov8i(d, s)     bpf_cmd(BPF_MOV |BPF_K|BPF_ALU, d, s, 8, 0)
#define bpf_smov16i(d, s)    bpf_cmd(BPF_MOV |BPF_K|BPF_ALU, d, s, 16, 0)
#define bpf_smov32i(d, s)    bpf_cmd(BPF_MOV |BPF_K|BPF_ALU, d, s, 32, 0)

#define bpf_add64(d, s)      bpf_cmd(BPF_ADD |BPF_X|BPF_ALU64, d, s, 0, 0)
#define bpf_sub64(d, s)      bpf_cmd(BPF_SUB |BPF_X|BPF_ALU64, d, s, 0, 0)
#define bpf_mul64(d, s)      bpf_cmd(BPF_MUL |BPF_X|BPF_ALU64, d, s, 0, 0)
#define bpf_div64(d, s)      bpf_cmd(BPF_DIV |BPF_X|BPF_ALU64, d, s, 0, 0)
#define bpf_or64(d, s)       bpf_cmd(BPF_OR  |BPF_X|BPF_ALU64, d, s, 0, 0)
#define bpf_and64(d, s)      bpf_cmd(BPF_AND |BPF_X|BPF_ALU64, d, s, 0, 0)
#define bpf_lsh64(d, s)      bpf_cmd(BPF_LSH |BPF_X|BPF_ALU64, d, s, 0, 0)
#define bpf_rsh64(d, s)      bpf_cmd(BPF_RSH |BPF_X|BPF_ALU64, d, s, 0, 0)
#define bpf_neg64(d)         bpf_cmd(BPF_NEG |BPF_X|BPF_ALU64, d, 0, 0, 0)
#define bpf_mod64(d, s)      bpf_cmd(BPF_MOD |BPF_X|BPF_ALU64, d, s, 0, 0)
#define bpf_xor64(d, s)      bpf_cmd(BPF_XOR |BPF_X|BPF_ALU64, d, s, 0, 0)
#define bpf_mov64(d, s)      bpf_cmd(BPF_MOV |BPF_X|BPF_ALU64, d, s, 0, 0)
#define bpf_arsh64(d, s)     bpf_cmd(BPF_ARSH|BPF_X|BPF_ALU64, d, s, 0, 0)
#define bpf_sdiv64(d, s)     bpf_cmd(BPF_DIV |BPF_X|BPF_ALU64, d, s, 1, 0)
#define bpf_smod64(d, s)     bpf_cmd(BPF_MOD |BPF_X|BPF_ALU64, d, s, 1, 0)

#define bpf_add64i(d, s)     bpf_cmd(BPF_ADD |BPF_K|BPF_ALU64, d, 0, 0, s)
#define bpf_sub64i(d, s)     bpf_cmd(BPF_SUB |BPF_K|BPF_ALU64, d, 0, 0, s)
#define bpf_mul64i(d, s)     bpf_cmd(BPF_MUL |BPF_K|BPF_ALU64, d, 0, 0, s)
#define bpf_div64i(d, s)     bpf_cmd(BPF_DIV |BPF_K|BPF_ALU64, d, 0, 0, s)
#define bpf_or64i(d, s)      bpf_cmd(BPF_OR  |BPF_K|BPF_ALU64, d, 0, 0, s)
#define bpf_and64i(d, s)     bpf_cmd(BPF_AND |BPF_K|BPF_ALU64, d, 0, 0, s)
#define bpf_lsh64i(d, s)     bpf_cmd(BPF_LSH |BPF_K|BPF_ALU64, d, 0, 0, s)
#define bpf_rsh64i(d, s)     bpf_cmd(BPF_RSH |BPF_K|BPF_ALU64, d, 0, 0, s)
#define bpf_mod64i(d, s)     bpf_cmd(BPF_MOD |BPF_K|BPF_ALU64, d, 0, 0, s)
#define bpf_xor64i(d, s)     bpf_cmd(BPF_XOR |BPF_K|BPF_ALU64, d, 0, 0, s)
#define bpf_mov64i(d, s)     bpf_cmd(BPF_MOV |BPF_K|BPF_ALU64, d, 0, 0, s)
#define bpf_arsh64i(d, s)    bpf_cmd(BPF_ARSH|BPF_K|BPF_ALU64, d, 0, 0, s)
#define bpf_sdiv64i(d, s)    bpf_cmd(BPF_DIV |BPF_K|BPF_ALU64, d, 0, 1, s)
#define bpf_smod64i(d, s)    bpf_cmd(BPF_MOD |BPF_K|BPF_ALU64, d, 0, 1, s)

#define bpf_be16(d)          bpf_cmd(BPF_END |BPF_TO_BE|BPF_ALU, d, 0, 0, 16)
#define bpf_be32(d)          bpf_cmd(BPF_END |BPF_TO_BE|BPF_ALU, d, 0, 0, 32)
#define bpf_be64(d)          bpf_cmd(BPF_END |BPF_TO_BE|BPF_ALU, d, 0, 0, 64)
#define bpf_le16(d)          bpf_cmd(BPF_END |BPF_TO_LE|BPF_ALU, d, 0, 0, 16)
#define bpf_le32(d)          bpf_cmd(BPF_END |BPF_TO_LE|BPF_ALU, d, 0, 0, 32)
#define bpf_le64(d)          bpf_cmd(BPF_END |BPF_TO_LE|BPF_ALU, d, 0, 0, 64)
#define bpf_swap16(d)        bpf_cmd(BPF_END |BPF_ALU64, d, 0, 0, 16)
#define bpf_swap32(d)        bpf_cmd(BPF_END |BPF_ALU64, d, 0, 0, 32)
#define bpf_swap64(d)        bpf_cmd(BPF_END |BPF_ALU64, d, 0, 0, 64)

#define bpf_jeq32(d, s, o)   bpf_cmd(BPF_JEQ  |BPF_X|BPF_JMP32, d, s, o, 0)
#define bpf_jne32(d, s, o)   bpf_cmd(BPF_JNE  |BPF_X|BPF_JMP32, d, s, o, 0)
#define bpf_jset32(d, s, o)  bpf_cmd(BPF_JSET |BPF_X|BPF_JMP32, d, s, o, 0)
#define bpf_jgt32(d, s, o)   bpf_cmd(BPF_JGT  |BPF_X|BPF_JMP32, d, s, o, 0)
#define bpf_jge32(d, s, o)   bpf_cmd(BPF_JGE  |BPF_X|BPF_JMP32, d, s, o, 0)
#define bpf_jsgt32(d, s, o)  bpf_cmd(BPF_JSGT |BPF_X|BPF_JMP32, d, s, o, 0)
#define bpf_jsge32(d, s, o)  bpf_cmd(BPF_JSGE |BPF_X|BPF_JMP32, d, s, o, 0)
#define bpf_jlt32(d, s, o)   bpf_cmd(BPF_JLT  |BPF_X|BPF_JMP32, d, s, o, 0)
#define bpf_jle32(d, s, o)   bpf_cmd(BPF_JLE  |BPF_X|BPF_JMP32, d, s, o, 0)
#define bpf_jslt32(d, s, o)  bpf_cmd(BPF_JSLT |BPF_X|BPF_JMP32, d, s, o, 0)
#define bpf_jsle32(d, s, o)  bpf_cmd(BPF_JSLE |BPF_X|BPF_JMP32, d, s, o, 0)

#define bpf_jeq32i(d, s, o)  bpf_cmd(BPF_JEQ  |BPF_K|BPF_JMP32, d, 0, o, s)
#define bpf_jne32i(d, s, o)  bpf_cmd(BPF_JNE  |BPF_K|BPF_JMP32, d, 0, o, s)
#define bpf_jset32i(d, s, o) bpf_cmd(BPF_JSET |BPF_K|BPF_JMP32, d, 0, o, s)
#define bpf_jgt32i(d, s, o)  bpf_cmd(BPF_JGT  |BPF_K|BPF_JMP32, d, 0, o, s)
#define bpf_jge32i(d, s, o)  bpf_cmd(BPF_JGE  |BPF_K|BPF_JMP32, d, 0, o, s)
#define bpf_jsgt32i(d, s, o) bpf_cmd(BPF_JSGT |BPF_K|BPF_JMP32, d, 0, o, s)
#define bpf_jsge32i(d, s, o) bpf_cmd(BPF_JSGE |BPF_K|BPF_JMP32, d, 0, o, s)
#define bpf_jlt32i(d, s, o)  bpf_cmd(BPF_JLT  |BPF_K|BPF_JMP32, d, 0, o, s)
#define bpf_jle32i(d, s, o)  bpf_cmd(BPF_JLE  |BPF_K|BPF_JMP32, d, 0, o, s)
#define bpf_jslt32i(d, s, o) bpf_cmd(BPF_JSLT |BPF_K|BPF_JMP32, d, 0, o, s)
#define bpf_jsle32i(d, s, o) bpf_cmd(BPF_JSLE |BPF_K|BPF_JMP32, d, 0, o, s)

#define bpf_jeq64(d, s, o)   bpf_cmd(BPF_JEQ  |BPF_X|BPF_JMP, d, s, o, 0)
#define bpf_jne64(d, s, o)   bpf_cmd(BPF_JNE  |BPF_X|BPF_JMP, d, s, o, 0)
#define bpf_jset64(d, s, o)  bpf_cmd(BPF_JSET |BPF_X|BPF_JMP, d, s, o, 0)
#define bpf_jgt64(d, s, o)   bpf_cmd(BPF_JGT  |BPF_X|BPF_JMP, d, s, o, 0)
#define bpf_jge64(d, s, o)   bpf_cmd(BPF_JGE  |BPF_X|BPF_JMP, d, s, o, 0)
#define bpf_jsgt64(d, s, o)  bpf_cmd(BPF_JSGT |BPF_X|BPF_JMP, d, s, o, 0)
#define bpf_jsge64(d, s, o)  bpf_cmd(BPF_JSGE |BPF_X|BPF_JMP, d, s, o, 0)
#define bpf_jlt64(d, s, o)   bpf_cmd(BPF_JLT  |BPF_X|BPF_JMP, d, s, o, 0)
#define bpf_jle64(d, s, o)   bpf_cmd(BPF_JLE  |BPF_X|BPF_JMP, d, s, o, 0)
#define bpf_jslt64(d, s, o)  bpf_cmd(BPF_JSLT |BPF_X|BPF_JMP, d, s, o, 0)
#define bpf_jsle64(d, s, o)  bpf_cmd(BPF_JSLE |BPF_X|BPF_JMP, d, s, o, 0)

#define bpf_jeq64i(d, s, o)  bpf_cmd(BPF_JEQ  |BPF_K|BPF_JMP, d, 0, o, s)
#define bpf_jne64i(d, s, o)  bpf_cmd(BPF_JNE  |BPF_K|BPF_JMP, d, 0, o, s)
#define bpf_jset64i(d, s, o) bpf_cmd(BPF_JSET |BPF_K|BPF_JMP, d, 0, o, s)
#define bpf_jgt64i(d, s, o)  bpf_cmd(BPF_JGT  |BPF_K|BPF_JMP, d, 0, o, s)
#define bpf_jge64i(d, s, o)  bpf_cmd(BPF_JGE  |BPF_K|BPF_JMP, d, 0, o, s)
#define bpf_jsgt64i(d, s, o) bpf_cmd(BPF_JSGT |BPF_K|BPF_JMP, d, 0, o, s)
#define bpf_jsge64i(d, s, o) bpf_cmd(BPF_JSGE |BPF_K|BPF_JMP, d, 0, o, s)
#define bpf_jlt64i(d, s, o)  bpf_cmd(BPF_JLT  |BPF_K|BPF_JMP, d, 0, o, s)
#define bpf_jle64i(d, s, o)  bpf_cmd(BPF_JLE  |BPF_K|BPF_JMP, d, 0, o, s)
#define bpf_jslt64i(d, s, o) bpf_cmd(BPF_JSLT |BPF_K|BPF_JMP, d, 0, o, s)
#define bpf_jsle64i(d, s, o) bpf_cmd(BPF_JSLE |BPF_K|BPF_JMP, d, 0, o, s)

#define bpf_ja32(o)          bpf_cmd(BPF_JA  |BPF_K|BPF_JMP32, 0, 0, 0, o)
#define bpf_ja64(o)          bpf_cmd(BPF_JA  |BPF_K|BPF_JMP64, 0, 0, o, 0)
#define bpf_call(id)         bpf_cmd(BPF_CALL|BPF_K|BPF_JMP, 0, 0, 0, id)
#define bpf_calli(o)         bpf_cmd(BPF_CALL|BPF_K|BPF_JMP, 0, 1, 0, o)
#define bpf_call_btf(id)     bpf_cmd(BPF_CALL|BPF_K|BPF_JMP, 0, 2, 0, id)
#define bpf_exit()           bpf_cmd(BPF_EXIT|BPF_K|BPF_JMP, 0, 0, 0, 0)

#define bpf_mst8(d, o, s)    bpf_cmd(BPF_MEM|BPF_B |BPF_STX, d, s, o, 0)
#define bpf_mst16(d, o, s)   bpf_cmd(BPF_MEM|BPF_H |BPF_STX, d, s, o, 0)
#define bpf_mst32(d, o, s)   bpf_cmd(BPF_MEM|BPF_W |BPF_STX, d, s, o, 0)
#define bpf_mst64(d, o, s)   bpf_cmd(BPF_MEM|BPF_DW|BPF_STX, d, s, o, 0)

#define bpf_mst8i(d, o, s)   bpf_cmd(BPF_MEM|BPF_B |BPF_ST, d, 0, o, s)
#define bpf_mst16i(d, o, s)  bpf_cmd(BPF_MEM|BPF_H |BPF_ST, d, 0, o, s)
#define bpf_mst32i(d, o, s)  bpf_cmd(BPF_MEM|BPF_W |BPF_ST, d, 0, o, s)
#define bpf_mst64i(d, o, s)  bpf_cmd(BPF_MEM|BPF_DW|BPF_ST, d, 0, o, s)

#define bpf_mld8(d, s, o)    bpf_cmd(BPF_MEM|BPF_B |BPF_LDX, d, s, o, 0)
#define bpf_mld16(d, s, o)   bpf_cmd(BPF_MEM|BPF_H |BPF_LDX, d, s, o, 0)
#define bpf_mld32(d, s, o)   bpf_cmd(BPF_MEM|BPF_W |BPF_LDX, d, s, o, 0)
#define bpf_mld64(d, s, o)   bpf_cmd(BPF_MEM|BPF_DW|BPF_LDX, d, s, o, 0)

#define bpf_mld8i(d, s, o)   bpf_cmd(BPF_MEM|BPF_B |BPF_LD, d, 0, o, s)
#define bpf_mld16i(d, s, o)  bpf_cmd(BPF_MEM|BPF_H |BPF_LD, d, 0, o, s)
#define bpf_mld32i(d, s, o)  bpf_cmd(BPF_MEM|BPF_W |BPF_LD, d, 0, o, s)
#define bpf_mld64i(d, s, o)  bpf_cmd(BPF_MEM|BPF_DW|BPF_LD, d, 0, o, s)

#define bpf_smst8(d, o, s)   bpf_cmd(BPF_MEMSX|BPF_B|BPF_STX, d, s, o, 0)
#define bpf_smst16(d, o, s)  bpf_cmd(BPF_MEMSX|BPF_H|BPF_STX, d, s, o, 0)
#define bpf_smst32(d, o, s)  bpf_cmd(BPF_MEMSX|BPF_W|BPF_STX, d, s, o, 0)

#define bpf_smst8i(d, o, s)  bpf_cmd(BPF_MEMSX|BPF_B|BPF_ST, d, 0, o, s)
#define bpf_smst16i(d, o, s) bpf_cmd(BPF_MEMSX|BPF_H|BPF_ST, d, 0, o, s)
#define bpf_smst32i(d, o, s) bpf_cmd(BPF_MEMSX|BPF_W|BPF_ST, d, 0, o, s)

#define bpf_smld8(d, s, o)   bpf_cmd(BPF_MEMSX|BPF_B|BPF_LDX, d, s, o, 0)
#define bpf_smld16(d, s, o)  bpf_cmd(BPF_MEMSX|BPF_H|BPF_LDX, d, s, o, 0)
#define bpf_smld32(d, s, o)  bpf_cmd(BPF_MEMSX|BPF_W|BPF_LDX, d, s, o, 0)

#define bpf_smld8i(d, s, o)  bpf_cmd(BPF_MEMSX|BPF_B|BPF_LD, d, 0, o, s)
#define bpf_smld16i(d, s, o) bpf_cmd(BPF_MEMSX|BPF_H|BPF_LD, d, 0, o, s)
#define bpf_smld32i(d, s, o) bpf_cmd(BPF_MEMSX|BPF_W|BPF_LD, d, 0, o, s)

#define bpf_atomic_add32(d, o, s) \
    bpf_cmd(BPF_ATOMIC|BPF_W|BPF_STX, d, s, o, BPF_ADD)
#define bpf_atomic_or32(d, o, s) \
    bpf_cmd(BPF_ATOMIC|BPF_W|BPF_STX, d, s, o, BPF_OR)
#define bpf_atomic_and32(d, o, s) \
    bpf_cmd(BPF_ATOMIC|BPF_W|BPF_STX, d, s, o, BPF_AND)
#define bpf_atomic_xor32(d, o, s) \
    bpf_cmd(BPF_ATOMIC|BPF_W|BPF_STX, d, s, o, BPF_XOR)

#define bpf_atomic_add64(d, o, s) \
    bpf_cmd(BPF_ATOMIC|BPF_DW|BPF_STX, d, s, o, BPF_ADD)
#define bpf_atomic_or64(d, o, s) \
    bpf_cmd(BPF_ATOMIC|BPF_DW|BPF_STX, d, s, o, BPF_OR)
#define bpf_atomic_and64(d, o, s) \
    bpf_cmd(BPF_ATOMIC|BPF_DW|BPF_STX, d, s, o, BPF_AND)
#define bpf_atomic_xor64(d, o, s) \
    bpf_cmd(BPF_ATOMIC|BPF_DW|BPF_STX, d, s, o, BPF_XOR)

#define bpf_imm64_ld(d, s, i) \
    bpf_cmd(BPF_IMM|BPF_DW|BPF_LD, d, s, 0, (__u32)(i)), \
    bpf_cmd(0, 0, 0, 0, ((__u64)(i)) >> 32)

#define bpf_load_fd(d, fd) bpf_imm64_ld(d, 0x1, fd)

#define ptr_to_u64(p) (__u64)(p)

static inline int
bpf_map_create(int *map, __u32 map_type, __u32 key_size, __u32 value_size,
    __u32 max_entries) {
    union bpf_attr attr = {0};
    attr.map_type = map_type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = max_entries;
    *map = syscall(__NR_bpf, BPF_MAP_CREATE, &attr,
        offsetofend(union bpf_attr, map_token_fd));
    return (*map == -1) ? errno : 0;
}

static inline int
bpf_map_lookup(__u32 map_fd, void *key, void *value) {
    union bpf_attr attr = {0};
    attr.map_fd = map_fd;
    attr.key = ptr_to_u64(key);
    attr.value = ptr_to_u64(value);
    if (syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr,
        offsetofend(union bpf_attr, flags)) == -1)
        return errno;
    return 0;
}

static inline int
bpf_prog_load(int *prog, __u32 prog_type, void *insns, __u64 insn_cnt,
    __u32 log_level, void *log_buf, __u32 log_size,
    char *license) {
    union bpf_attr attr = {0};

    if (log_level == 0) {
        TRY(log_buf == NULL, return EINVAL);
        TRY(log_size == 0, return EINVAL);
    }
    TRY(license, return EINVAL);

    attr.prog_type = prog_type;
    attr.insns = ptr_to_u64(insns);
    attr.insn_cnt = insn_cnt;
    attr.license = ptr_to_u64(license);
    attr.log_level = log_level;
    attr.log_buf = ptr_to_u64(log_buf);
    attr.log_size = log_size;
    *prog = syscall(__NR_bpf, BPF_PROG_LOAD, &attr,
        offsetofend(union bpf_attr, prog_token_fd));
    return (*prog == -1) ? errno : 0;
}

static inline void
bpf_prog_dump(void *buf, size_t size) {
    size_t _s = sizeof(struct bpf_insn);
    for (size_t i = 0; i < (size); i++) {
        if (i % _s == 0) printf("[%08ld] ", i / _s);
        printf("%02x ", ((uint8_t*)buf)[i]);
        if (i % _s == _s - 1) printf("\n");
    }
}

static inline int
if_attach(int *sock, char *name, int bpf) {
    struct sockaddr_ll addr = {0};
    int ret = 0;

    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = if_nametoindex(name);
    addr.sll_protocol = htons(ETH_P_ALL);

    TRY((*sock = socket(PF_PACKET,
        SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL))) != -1,
        return errno);
    TRY(!bind(*sock, (struct sockaddr *)&addr, sizeof(addr)),
        RETURN(errno, err));
    TRY(!setsockopt(*sock, SOL_SOCKET, SO_ATTACH_BPF, &bpf, sizeof(bpf)),
        RETURN(errno, err));
err:
    if (ret) {
        close(*sock);
        *sock = -1;
    }
    return ret;
}

#endif

