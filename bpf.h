#ifndef __BPF_H__
#define __BPF_H__

#include <stdio.h>
#include <stdlib.h>
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

/*
  - RFC9669: https://www.rfc-editor.org/rfc/rfc9669.txt
  - Linux: https://docs.kernel.org/bpf/index.html
*/

#define KB 1024
#define MB (KB * KB)
#define GB (GB * GB)

#define LEN(x) (int)(sizeof(x) / sizeof((x)[0]))
#define ZEROS(x, n) bzero(x, n)
#define ZERO(x) ZEROS(&(x), sizeof(x))
#define NOBREAK __attribute__((fallthrough))

#define LOG(fmt, arg...) printf(fmt, ##arg);
#define _LOGERR(tag, fmt, arg...) do { \
    printf("\033[38;5;1m"); \
    printf("[%s %d] [%s] " fmt, __FILE__, __LINE__, tag, ##arg); \
    printf("\033[38;5;15m"); \
} while(0)

#define LOGERR(fmt, arg...) _LOGERR("ERROR", fmt, ##arg)
#define _TRYF(exp, tag, next, fmt, arg...) ({ \
    if (!(exp)) { \
        _LOGERR(tag, "`%s`" fmt, #exp, ##arg); \
        next; \
    } \
    1; \
})

#define TRYF(exp, next, fmt, arg...) \
    _TRYF(exp, "TRY", next, fmt, ##arg)
#define TRY(exp, next) TRYF(exp, next, "\n")
#define ASSERTF(exp, fmt, arg...) \
    _TRYF(exp, "ASSERT", _exit(1), fmt,  ##arg)
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
#define bpf_fp BPF_REG_10

#define bpf_ins(_code, _dst_reg, _src_reg, _off, _imm) \
    ((struct bpf_insn) { \
        .code  = _code, \
        .dst_reg = _dst_reg, \
        .src_reg = _src_reg, \
        .off = (__u16)(_off), \
        .imm   = (__u32)(_imm)})

#define BPF_R    BPF_X
#define BPF_I    BPF_K
#define BPF_1    BPF_B
#define BPF_2    BPF_H
#define BPF_4    BPF_W
#define BPF_8    BPF_DW
#define BPF_ATOM BPF_ATOMIC
#define BPF_SMEM BPF_MEMSX
#define BPF_ALU4 BPF_ALU
#define BPF_ALU8 BPF_ALU64
#define BPF_JMP4 BPF_JMP32
#define BPF_JMP8 BPF_JMP

#define bpf_add4(d, s)      bpf_ins(BPF_ADD |BPF_R|BPF_ALU4, d, s, 0, 0)
#define bpf_sub4(d, s)      bpf_ins(BPF_SUB |BPF_R|BPF_ALU4, d, s, 0, 0)
#define bpf_mul4(d, s)      bpf_ins(BPF_MUL |BPF_R|BPF_ALU4, d, s, 0, 0)
#define bpf_div4(d, s)      bpf_ins(BPF_DIV |BPF_R|BPF_ALU4, d, s, 0, 0)
#define bpf_or4(d, s)       bpf_ins(BPF_OR  |BPF_R|BPF_ALU4, d, s, 0, 0)
#define bpf_and4(d, s)      bpf_ins(BPF_AND |BPF_R|BPF_ALU4, d, s, 0, 0)
#define bpf_lsh4(d, s)      bpf_ins(BPF_LSH |BPF_R|BPF_ALU4, d, s, 0, 0)
#define bpf_rsh4(d, s)      bpf_ins(BPF_RSH |BPF_R|BPF_ALU4, d, s, 0, 0)
#define bpf_mod4(d, s)      bpf_ins(BPF_MOD |BPF_R|BPF_ALU4, d, s, 0, 0)
#define bpf_xor4(d, s)      bpf_ins(BPF_ROR |BPF_R|BPF_ALU4, d, s, 0, 0)
#define bpf_mov4(d, s)      bpf_ins(BPF_MOV |BPF_R|BPF_ALU4, d, s, 0, 0)
#define bpf_arsh4(d, s)     bpf_ins(BPF_ARSH|BPF_R|BPF_ALU4, d, s, 0, 0)
#define bpf_sdiv4(d, s)     bpf_ins(BPF_DIV |BPF_R|BPF_ALU4, d, s, 1, 0)
#define bpf_smod4(d, s)     bpf_ins(BPF_MOD |BPF_R|BPF_ALU4, d, s, 1, 0)
#define bpf_add4i(d, s)     bpf_ins(BPF_ADD |BPF_I|BPF_ALU4, d, 0, 0, s)
#define bpf_sub4i(d, s)     bpf_ins(BPF_SUB |BPF_I|BPF_ALU4, d, 0, 0, s)
#define bpf_mul4i(d, s)     bpf_ins(BPF_MUL |BPF_I|BPF_ALU4, d, 0, 0, s)
#define bpf_div4i(d, s)     bpf_ins(BPF_DIV |BPF_I|BPF_ALU4, d, 0, 0, s)
#define bpf_or4i(d, s)      bpf_ins(BPF_OR  |BPF_I|BPF_ALU4, d, 0, 0, s)
#define bpf_and4i(d, s)     bpf_ins(BPF_AND |BPF_I|BPF_ALU4, d, 0, 0, s)
#define bpf_lsh4i(d, s)     bpf_ins(BPF_LSH |BPF_I|BPF_ALU4, d, 0, 0, s)
#define bpf_rsh4i(d, s)     bpf_ins(BPF_RSH |BPF_I|BPF_ALU4, d, 0, 0, s)
#define bpf_mod4i(d, s)     bpf_ins(BPF_MOD |BPF_I|BPF_ALU4, d, 0, 0, s)
#define bpf_xor4i(d, s)     bpf_ins(BPF_ROR |BPF_I|BPF_ALU4, d, 0, 0, s)
#define bpf_mov4i(d, s)     bpf_ins(BPF_MOV |BPF_I|BPF_ALU4, d, 0, 0, s)
#define bpf_arsh4i(d, s)    bpf_ins(BPF_ARSH|BPF_I|BPF_ALU4, d, 0, 0, s)
#define bpf_neg4(d)         bpf_ins(BPF_NEG |BPF_I|BPF_ALU4, d, 0, 0, 0)
#define bpf_sdiv4i(d, s)    bpf_ins(BPF_DIV |BPF_I|BPF_ALU4, d, 0, 1, s)
#define bpf_smod4i(d, s)    bpf_ins(BPF_MOD |BPF_I|BPF_ALU4, d, 0, 1, s)
#define bpf_add8(d, s)      bpf_ins(BPF_ADD |BPF_R|BPF_ALU8, d, s, 0, 0)
#define bpf_sub8(d, s)      bpf_ins(BPF_SUB |BPF_R|BPF_ALU8, d, s, 0, 0)
#define bpf_mul8(d, s)      bpf_ins(BPF_MUL |BPF_R|BPF_ALU8, d, s, 0, 0)
#define bpf_div8(d, s)      bpf_ins(BPF_DIV |BPF_R|BPF_ALU8, d, s, 0, 0)
#define bpf_or8(d, s)       bpf_ins(BPF_OR  |BPF_R|BPF_ALU8, d, s, 0, 0)
#define bpf_and8(d, s)      bpf_ins(BPF_AND |BPF_R|BPF_ALU8, d, s, 0, 0)
#define bpf_lsh8(d, s)      bpf_ins(BPF_LSH |BPF_R|BPF_ALU8, d, s, 0, 0)
#define bpf_rsh8(d, s)      bpf_ins(BPF_RSH |BPF_R|BPF_ALU8, d, s, 0, 0)
#define bpf_mod8(d, s)      bpf_ins(BPF_MOD |BPF_R|BPF_ALU8, d, s, 0, 0)
#define bpf_xor8(d, s)      bpf_ins(BPF_ROR |BPF_R|BPF_ALU8, d, s, 0, 0)
#define bpf_mov8(d, s)      bpf_ins(BPF_MOV |BPF_R|BPF_ALU8, d, s, 0, 0)
#define bpf_arsh8(d, s)     bpf_ins(BPF_ARSH|BPF_R|BPF_ALU8, d, s, 0, 0)
#define bpf_sdiv8(d, s)     bpf_ins(BPF_DIV |BPF_R|BPF_ALU8, d, s, 1, 0)
#define bpf_smod8(d, s)     bpf_ins(BPF_MOD |BPF_R|BPF_ALU8, d, s, 1, 0)
#define bpf_add8i(d, s)     bpf_ins(BPF_ADD |BPF_I|BPF_ALU8, d, 0, 0, s)
#define bpf_sub8i(d, s)     bpf_ins(BPF_SUB |BPF_I|BPF_ALU8, d, 0, 0, s)
#define bpf_mul8i(d, s)     bpf_ins(BPF_MUL |BPF_I|BPF_ALU8, d, 0, 0, s)
#define bpf_div8i(d, s)     bpf_ins(BPF_DIV |BPF_I|BPF_ALU8, d, 0, 0, s)
#define bpf_or8i(d, s)      bpf_ins(BPF_OR  |BPF_I|BPF_ALU8, d, 0, 0, s)
#define bpf_and8i(d, s)     bpf_ins(BPF_AND |BPF_I|BPF_ALU8, d, 0, 0, s)
#define bpf_lsh8i(d, s)     bpf_ins(BPF_LSH |BPF_I|BPF_ALU8, d, 0, 0, s)
#define bpf_rsh8i(d, s)     bpf_ins(BPF_RSH |BPF_I|BPF_ALU8, d, 0, 0, s)
#define bpf_mod8i(d, s)     bpf_ins(BPF_MOD |BPF_I|BPF_ALU8, d, 0, 0, s)
#define bpf_xor8i(d, s)     bpf_ins(BPF_ROR |BPF_I|BPF_ALU8, d, 0, 0, s)
#define bpf_mov8i(d, s)     bpf_ins(BPF_MOV |BPF_I|BPF_ALU8, d, 0, 0, s)
#define bpf_arsh8i(d, s)    bpf_ins(BPF_ARSH|BPF_I|BPF_ALU8, d, 0, 0, s)
#define bpf_neg8(d)         bpf_ins(BPF_NEG |BPF_I|BPF_ALU8, d, 0, 0, 0)
#define bpf_sdiv8i(d, s)    bpf_ins(BPF_DIV |BPF_I|BPF_ALU8, d, 0, 1, s)
#define bpf_smod8i(d, s)    bpf_ins(BPF_MOD |BPF_I|BPF_ALU8, d, 0, 1, s)
#define bpf_smov1to4(d, s)  bpf_ins(BPF_MOV |BPF_R|BPF_ALU4, d, s, 8, 0)
#define bpf_smov2to4(d, s)  bpf_ins(BPF_MOV |BPF_R|BPF_ALU4, d, s, 16, 0)
#define bpf_smov1to8(d, s)  bpf_ins(BPF_MOV |BPF_I|BPF_ALU8, d, s, 8, 0)
#define bpf_smov2to8(d, s)  bpf_ins(BPF_MOV |BPF_I|BPF_ALU8, d, s, 16, 0)
#define bpf_smov4to8(d, s)  bpf_ins(BPF_MOV |BPF_I|BPF_ALU8, d, s, 32, 0)

#define bpf_be2(d)          bpf_ins(BPF_END |BPF_TO_BE|BPF_ALU4, d, 0, 0, 16)
#define bpf_be4(d)          bpf_ins(BPF_END |BPF_TO_BE|BPF_ALU4, d, 0, 0, 32)
#define bpf_be8(d)          bpf_ins(BPF_END |BPF_TO_BE|BPF_ALU4, d, 0, 0, 64)
#define bpf_le2(d)          bpf_ins(BPF_END |BPF_TO_LE|BPF_ALU4, d, 0, 0, 16)
#define bpf_le4(d)          bpf_ins(BPF_END |BPF_TO_LE|BPF_ALU4, d, 0, 0, 32)
#define bpf_le8(d)          bpf_ins(BPF_END |BPF_TO_LE|BPF_ALU4, d, 0, 0, 64)
#define bpf_swap2(d)        bpf_ins(BPF_END |BPF_ALU8,           d, 0, 0, 16)
#define bpf_swap4(d)        bpf_ins(BPF_END |BPF_ALU8,           d, 0, 0, 32)
#define bpf_swap8(d)        bpf_ins(BPF_END |BPF_ALU8,           d, 0, 0, 64)

#define bpf_jeq4(d, s, o)   bpf_ins(BPF_JEQ  |BPF_R|BPF_JMP4, d, s, o, 0)
#define bpf_jne4(d, s, o)   bpf_ins(BPF_JNE  |BPF_R|BPF_JMP4, d, s, o, 0)
#define bpf_jset4(d, s, o)  bpf_ins(BPF_JSET |BPF_R|BPF_JMP4, d, s, o, 0)
#define bpf_jgt4(d, s, o)   bpf_ins(BPF_JGT  |BPF_R|BPF_JMP4, d, s, o, 0)
#define bpf_jge4(d, s, o)   bpf_ins(BPF_JGE  |BPF_R|BPF_JMP4, d, s, o, 0)
#define bpf_jsgt4(d, s, o)  bpf_ins(BPF_JSGT |BPF_R|BPF_JMP4, d, s, o, 0)
#define bpf_jsge4(d, s, o)  bpf_ins(BPF_JSGE |BPF_R|BPF_JMP4, d, s, o, 0)
#define bpf_jlt4(d, s, o)   bpf_ins(BPF_JLT  |BPF_R|BPF_JMP4, d, s, o, 0)
#define bpf_jle4(d, s, o)   bpf_ins(BPF_JLE  |BPF_R|BPF_JMP4, d, s, o, 0)
#define bpf_jslt4(d, s, o)  bpf_ins(BPF_JSLT |BPF_R|BPF_JMP4, d, s, o, 0)
#define bpf_jsle4(d, s, o)  bpf_ins(BPF_JSLE |BPF_R|BPF_JMP4, d, s, o, 0)
#define bpf_jeq4i(d, s, o)  bpf_ins(BPF_JEQ  |BPF_I|BPF_JMP4, d, 0, o, s)
#define bpf_jne4i(d, s, o)  bpf_ins(BPF_JNE  |BPF_I|BPF_JMP4, d, 0, o, s)
#define bpf_jset4i(d, s, o) bpf_ins(BPF_JSET |BPF_I|BPF_JMP4, d, 0, o, s)
#define bpf_jgt4i(d, s, o)  bpf_ins(BPF_JGT  |BPF_I|BPF_JMP4, d, 0, o, s)
#define bpf_jge4i(d, s, o)  bpf_ins(BPF_JGE  |BPF_I|BPF_JMP4, d, 0, o, s)
#define bpf_jsgt4i(d, s, o) bpf_ins(BPF_JSGT |BPF_I|BPF_JMP4, d, 0, o, s)
#define bpf_jsge4i(d, s, o) bpf_ins(BPF_JSGE |BPF_I|BPF_JMP4, d, 0, o, s)
#define bpf_jlt4i(d, s, o)  bpf_ins(BPF_JLT  |BPF_I|BPF_JMP4, d, 0, o, s)
#define bpf_jle4i(d, s, o)  bpf_ins(BPF_JLE  |BPF_I|BPF_JMP4, d, 0, o, s)
#define bpf_jslt4i(d, s, o) bpf_ins(BPF_JSLT |BPF_I|BPF_JMP4, d, 0, o, s)
#define bpf_jsle4i(d, s, o) bpf_ins(BPF_JSLE |BPF_I|BPF_JMP4, d, 0, o, s)
#define bpf_jeq8(d, s, o)   bpf_ins(BPF_JEQ  |BPF_R|BPF_JMP8, d, s, o, 0)
#define bpf_jne8(d, s, o)   bpf_ins(BPF_JNE  |BPF_R|BPF_JMP8, d, s, o, 0)
#define bpf_jset8(d, s, o)  bpf_ins(BPF_JSET |BPF_R|BPF_JMP8, d, s, o, 0)
#define bpf_jgt8(d, s, o)   bpf_ins(BPF_JGT  |BPF_R|BPF_JMP8, d, s, o, 0)
#define bpf_jge8(d, s, o)   bpf_ins(BPF_JGE  |BPF_R|BPF_JMP8, d, s, o, 0)
#define bpf_jsgt8(d, s, o)  bpf_ins(BPF_JSGT |BPF_R|BPF_JMP8, d, s, o, 0)
#define bpf_jsge8(d, s, o)  bpf_ins(BPF_JSGE |BPF_R|BPF_JMP8, d, s, o, 0)
#define bpf_jlt8(d, s, o)   bpf_ins(BPF_JLT  |BPF_R|BPF_JMP8, d, s, o, 0)
#define bpf_jle8(d, s, o)   bpf_ins(BPF_JLE  |BPF_R|BPF_JMP8, d, s, o, 0)
#define bpf_jslt8(d, s, o)  bpf_ins(BPF_JSLT |BPF_R|BPF_JMP8, d, s, o, 0)
#define bpf_jsle8(d, s, o)  bpf_ins(BPF_JSLE |BPF_R|BPF_JMP8, d, s, o, 0)
#define bpf_jeq8i(d, s, o)  bpf_ins(BPF_JEQ  |BPF_I|BPF_JMP8, d, 0, o, s)
#define bpf_jne8i(d, s, o)  bpf_ins(BPF_JNE  |BPF_I|BPF_JMP8, d, 0, o, s)
#define bpf_jset8i(d, s, o) bpf_ins(BPF_JSET |BPF_I|BPF_JMP8, d, 0, o, s)
#define bpf_jgt8i(d, s, o)  bpf_ins(BPF_JGT  |BPF_I|BPF_JMP8, d, 0, o, s)
#define bpf_jge8i(d, s, o)  bpf_ins(BPF_JGE  |BPF_I|BPF_JMP8, d, 0, o, s)
#define bpf_jsgt8i(d, s, o) bpf_ins(BPF_JSGT |BPF_I|BPF_JMP8, d, 0, o, s)
#define bpf_jsge8i(d, s, o) bpf_ins(BPF_JSGE |BPF_I|BPF_JMP8, d, 0, o, s)
#define bpf_jlt8i(d, s, o)  bpf_ins(BPF_JLT  |BPF_I|BPF_JMP8, d, 0, o, s)
#define bpf_jle8i(d, s, o)  bpf_ins(BPF_JLE  |BPF_I|BPF_JMP8, d, 0, o, s)
#define bpf_jslt8i(d, s, o) bpf_ins(BPF_JSLT |BPF_I|BPF_JMP8, d, 0, o, s)
#define bpf_jsle8i(d, s, o) bpf_ins(BPF_JSLE |BPF_I|BPF_JMP8, d, 0, o, s)
#define bpf_ja4(o)          bpf_ins(BPF_JA   |BPF_I|BPF_JMP4, 0, 0, 0, o)
#define bpf_ja8(o)          bpf_ins(BPF_JA   |BPF_I|BPF_JMP8, 0, 0, o, 0)
#define bpf_call(i)         bpf_ins(BPF_CALL |BPF_I|BPF_JMP8, 0, 0, 0, i)
#define bpf_calli(i)        bpf_ins(BPF_CALL |BPF_I|BPF_JMP8, 0, 1, 0, i)
#define bpf_call_btf(i)     bpf_ins(BPF_CALL |BPF_I|BPF_JMP8, 0, 2, 0, i)
#define bpf_exit()          bpf_ins(BPF_EXIT |BPF_I|BPF_JMP8, 0, 0, 0, 0)

// store: *(size*)(dst + offset) = src
#define bpf_mst1(d, o, s)   bpf_ins(BPF_MEM |BPF_1|BPF_STX, d, s, o, 0)
#define bpf_mst2(d, o, s)   bpf_ins(BPF_MEM |BPF_2|BPF_STX, d, s, o, 0)
#define bpf_mst4(d, o, s)   bpf_ins(BPF_MEM |BPF_4|BPF_STX, d, s, o, 0)
#define bpf_mst8(d, o, s)   bpf_ins(BPF_MEM |BPF_8|BPF_STX, d, s, o, 0)
#define bpf_smst1(d, o, s)  bpf_ins(BPF_SMEM|BPF_1|BPF_STX, d, s, o, 0)
#define bpf_smst2(d, o, s)  bpf_ins(BPF_SMEM|BPF_2|BPF_STX, d, s, o, 0)
#define bpf_smst4(d, o, s)  bpf_ins(BPF_SMEM|BPF_4|BPF_STX, d, s, o, 0)
#define bpf_mst1i(d, o, s)  bpf_ins(BPF_MEM |BPF_1|BPF_ST,  d, 0, o, s)
#define bpf_mst2i(d, o, s)  bpf_ins(BPF_MEM |BPF_2|BPF_ST,  d, 0, o, s)
#define bpf_mst4i(d, o, s)  bpf_ins(BPF_MEM |BPF_4|BPF_ST,  d, 0, o, s)
#define bpf_mst8i(d, o, s)  bpf_ins(BPF_MEM |BPF_8|BPF_ST,  d, 0, o, s)
#define bpf_smst1i(d, o, s) bpf_ins(BPF_SMEM|BPF_1|BPF_ST,  d, 0, o, s)
#define bpf_smst2i(d, o, s) bpf_ins(BPF_SMEM|BPF_2|BPF_ST,  d, 0, o, s)
#define bpf_smst4i(d, o, s) bpf_ins(BPF_SMEM|BPF_4|BPF_ST,  d, 0, o, s)

// load: dst = *(size*)(src + offset)
#define bpf_mld1(d, s, o)   bpf_ins(BPF_MEM |BPF_1|BPF_LDX, d, s, o, 0)
#define bpf_mld2(d, s, o)   bpf_ins(BPF_MEM |BPF_2|BPF_LDX, d, s, o, 0)
#define bpf_mld4(d, s, o)   bpf_ins(BPF_MEM |BPF_4|BPF_LDX, d, s, o, 0)
#define bpf_mld8(d, s, o)   bpf_ins(BPF_MEM |BPF_8|BPF_LDX, d, s, o, 0)
#define bpf_smld1(d, s, o)  bpf_ins(BPF_SMEM|BPF_1|BPF_LDX, d, s, o, 0)
#define bpf_smld2(d, s, o)  bpf_ins(BPF_SMEM|BPF_2|BPF_LDX, d, s, o, 0)
#define bpf_smld4(d, s, o)  bpf_ins(BPF_SMEM|BPF_4|BPF_LDX, d, s, o, 0)
#define bpf_mld1i(d, s, o)  bpf_ins(BPF_MEM |BPF_1|BPF_LD,  d, 0, o, s)
#define bpf_mld2i(d, s, o)  bpf_ins(BPF_MEM |BPF_2|BPF_LD,  d, 0, o, s)
#define bpf_mld4i(d, s, o)  bpf_ins(BPF_MEM |BPF_4|BPF_LD,  d, 0, o, s)
#define bpf_mld8i(d, s, o)  bpf_ins(BPF_MEM |BPF_8|BPF_LD,  d, 0, o, s)
#define bpf_smld1i(d, s, o) bpf_ins(BPF_SMEM|BPF_1|BPF_LD,  d, 0, o, s)
#define bpf_smld2i(d, s, o) bpf_ins(BPF_SMEM|BPF_2|BPF_LD,  d, 0, o, s)
#define bpf_smld4i(d, s, o) bpf_ins(BPF_SMEM|BPF_4|BPF_LD,  d, 0, o, s)

// atomic: *(size*)(dst + offset) += src
#define _BPF_ATOM BPF_ATOM|BPF_STX
#define bpf_atom_add4(d, o, s) bpf_ins(_BPF_ATOM|BPF_4, d, s, o, BPF_ADD)
#define bpf_atom_or4(d, o, s)  bpf_ins(_BPF_ATOM|BPF_4, d, s, o, BPF_OR)
#define bpf_atom_and4(d, o, s) bpf_ins(_BPF_ATOM|BPF_4, d, s, o, BPF_AND)
#define bpf_atom_xor4(d, o, s) bpf_ins(_BPF_ATOM|BPF_4, d, s, o, BPF_XOR)
#define bpf_atom_add8(d, o, s) bpf_ins(_BPF_ATOM|BPF_8, d, s, o, BPF_ADD)
#define bpf_atom_or8(d, o, s)  bpf_ins(_BPF_ATOM|BPF_8, d, s, o, BPF_OR)
#define bpf_atom_and8(d, o, s) bpf_ins(_BPF_ATOM|BPF_8, d, s, o, BPF_AND)
#define bpf_atom_xor8(d, o, s) bpf_ins(_BPF_ATOM|BPF_8, d, s, o, BPF_XOR)

#define bpf_imm8_ld(d, s, i) \
    bpf_ins(BPF_IMM|BPF_8|BPF_LD, d, s, 0, (__u64)(i)), \
    bpf_ins(0, 0, 0, 0, ((__u64)(i)) >> 32)

#define bpf_imm8_int_ld(d, i)  bpf_imm8_ld(d, 0x0, i)
#define bpf_imm8_map_ld(d, fd) bpf_imm8_ld(d, 0x1, fd)
#define bpf_return(r) \
    bpf_mov8i(bpf_r0, r), \
    bpf_exit()

#define ptr_to_u64(p) (__u64)(p)

static inline char*
bpf_ins_string(struct bpf_insn *ins) {
    static char buf[128];
    char s1[5] = {'?'};
    char s2[2] = {'?'};
    char s3[5] = {'?'};

#define _case1(t) case BPF_##t: snprintf(s1, sizeof(s1), "%s", #t); break;
#define _case2(t) case BPF_##t: snprintf(s2, sizeof(s2), "%s", #t); break;
#define _case3(t) case BPF_##t: snprintf(s3, sizeof(s3), "%s", #t);

    memset(&buf, ' ', sizeof(buf));
    buf[sizeof(buf)-1] = 0;
    switch (BPF_CLASS(ins->code)) {
    _case3(ALU4) NOBREAK;
    _case3(ALU8)
        sprintf(s3, "ALU8");
        switch (BPF_OP(ins->code)) {
        _case1(ADD);
        _case1(SUB);
        _case1(MUL);
        _case1(DIV);
        _case1(OR);
        _case1(AND);
        _case1(LSH);
        _case1(RSH);
        _case1(NEG);
        _case1(MOD);
        _case1(XOR);
        _case1(MOV);
        _case1(ARSH);
        _case1(END);
        }
        switch (BPF_SRC(ins->code)) {
        _case2(I);
        _case2(R);
        }
        break;
    _case3(JMP4) NOBREAK;
    _case3(JMP8)
        switch(BPF_OP(ins->code)) {
        _case1(JEQ);
        _case1(JNE);
        _case1(JSET);
        _case1(JGT);
        _case1(JGE);
        _case1(JSGT);
        _case1(JSGE);
        _case1(JLT);
        _case1(JLE);
        _case1(JSLT);
        _case1(JSLE);
        _case1(CALL);
        _case1(EXIT);
        }
        switch (BPF_SRC(ins->code)) {
        _case2(I);
        _case2(R);
        }
        break;
    _case3(ST) NOBREAK;
    _case3(STX) NOBREAK;
    _case3(LD) NOBREAK;
    _case3(LDX)
        switch (BPF_MODE(ins->code)) {
        _case1(IMM);
        _case1(MEM);
        _case1(ATOM);
        _case1(SMEM);
        }
        switch (BPF_SIZE(ins->code)) {
        _case2(1);
        _case2(2);
        _case2(4);
        _case2(8);
        }
    }

#undef _case1
#undef _case2
#undef _case3

    snprintf(buf, sizeof(buf), "%4s %s %4s %x %x %8d %8ld",
        s1, s2, s3, ins->dst_reg, ins->src_reg,
        (int32_t)ins->off, (int64_t)ins->imm);
    return buf;
}

static inline void
bpf_prog_print(struct bpf_insn *insns, size_t insn_cnt) {
    char buf[128];
    int n;
    snprintf(buf, sizeof(buf), "%ld", insn_cnt);
    n = strlen(buf);
    for (size_t i = 0; i < insn_cnt; i++)
        LOG("%*ld %s\n", n, i, bpf_ins_string(&insns[i]));
}

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
bpf_prog_load(int *prog, __u32 prog_type, struct bpf_insn *insns,
    __u32 insn_cnt, char *license, uint32_t dump) {
    union bpf_attr attr = {0};
    char *log = NULL;
    int level = 0;

    TRY(license, return EINVAL);

    if (dump > 0) {
        TRY(log = malloc(dump), return ENOMEM);
        ZEROS(log, dump);
        level = 2;
    }

    attr.prog_type = prog_type;
    attr.insns = ptr_to_u64(insns);
    attr.insn_cnt = insn_cnt;
    attr.license = ptr_to_u64(license);
    attr.log_level = level;
    attr.log_buf = ptr_to_u64(log);
    attr.log_size = dump;
    *prog = syscall(__NR_bpf, BPF_PROG_LOAD, &attr,
        offsetofend(union bpf_attr, prog_token_fd));

    if (dump > 0) {
        LOG("%s\n", log);
        free(log);
    }
    return (*prog == -1) ? errno : 0;
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
