#ifndef __BPF_H__
#define __BPF_H__

#include <linux/ip.h>
#include <linux/bpf.h>
#include <arpa/inet.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>

/*
  - RFC9669: https://www.rfc-editor.org/rfc/rfc9669.txt
  - Linux: https://docs.kernel.org/bpf/index.html
*/

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
#define BPF_ALU4 BPF_ALU
#define BPF_ALU8 BPF_ALU64
#define BPF_JMP4 BPF_JMP32
#define BPF_JMP8 BPF_JMP

#ifdef BPF_MEMSX
#define BPF_SMEM BPF_MEMSX
#endif

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
#define bpf_jai(o)          bpf_ins(BPF_JA   |BPF_I|BPF_JMP4, 0, 0, 0, o)
#define bpf_ja(o)           bpf_ins(BPF_JA   |BPF_I|BPF_JMP8, 0, 0, o, 0)
#define bpf_call(i)         bpf_ins(BPF_CALL |BPF_I|BPF_JMP8, 0, 0, 0, \
                                        BPF_FUNC_##i)
#define bpf_calli(i)        bpf_ins(BPF_CALL |BPF_I|BPF_JMP8, 0, 1, 0, i)
#define bpf_call_btf(i)     bpf_ins(BPF_CALL |BPF_I|BPF_JMP8, 0, 2, 0, i)
#define bpf_exit()          bpf_ins(BPF_EXIT |BPF_I|BPF_JMP8, 0, 0, 0, 0)

// store: *(size*)(dst + offset) = src
#define bpf_st1(d, o, s)   bpf_ins(BPF_MEM |BPF_1|BPF_STX, d, s, o, 0)
#define bpf_st2(d, o, s)   bpf_ins(BPF_MEM |BPF_2|BPF_STX, d, s, o, 0)
#define bpf_st4(d, o, s)   bpf_ins(BPF_MEM |BPF_4|BPF_STX, d, s, o, 0)
#define bpf_st8(d, o, s)   bpf_ins(BPF_MEM |BPF_8|BPF_STX, d, s, o, 0)
#define bpf_st1i(d, o, s)  bpf_ins(BPF_MEM |BPF_1|BPF_ST,  d, 0, o, s)
#define bpf_st2i(d, o, s)  bpf_ins(BPF_MEM |BPF_2|BPF_ST,  d, 0, o, s)
#define bpf_st4i(d, o, s)  bpf_ins(BPF_MEM |BPF_4|BPF_ST,  d, 0, o, s)
#define bpf_st8i(d, o, s)  bpf_ins(BPF_MEM |BPF_8|BPF_ST,  d, 0, o, s)
#ifdef BPF_SMEM
#define bpf_sst1(d, o, s)  bpf_ins(BPF_SMEM|BPF_1|BPF_STX, d, s, o, 0)
#define bpf_sst2(d, o, s)  bpf_ins(BPF_SMEM|BPF_2|BPF_STX, d, s, o, 0)
#define bpf_sst4(d, o, s)  bpf_ins(BPF_SMEM|BPF_4|BPF_STX, d, s, o, 0)
#define bpf_sst1i(d, o, s) bpf_ins(BPF_SMEM|BPF_1|BPF_ST,  d, 0, o, s)
#define bpf_sst2i(d, o, s) bpf_ins(BPF_SMEM|BPF_2|BPF_ST,  d, 0, o, s)
#define bpf_sst4i(d, o, s) bpf_ins(BPF_SMEM|BPF_4|BPF_ST,  d, 0, o, s)
#endif

// load: dst = *(size*)(src + offset)
#define bpf_ld1(d, s, o)   bpf_ins(BPF_MEM |BPF_1|BPF_LDX, d, s, o, 0)
#define bpf_ld2(d, s, o)   bpf_ins(BPF_MEM |BPF_2|BPF_LDX, d, s, o, 0)
#define bpf_ld4(d, s, o)   bpf_ins(BPF_MEM |BPF_4|BPF_LDX, d, s, o, 0)
#define bpf_ld8(d, s, o)   bpf_ins(BPF_MEM |BPF_8|BPF_LDX, d, s, o, 0)
#define bpf_ld1i(d, s, o)  bpf_ins(BPF_MEM |BPF_1|BPF_LD,  d, 0, o, s)
#define bpf_ld2i(d, s, o)  bpf_ins(BPF_MEM |BPF_2|BPF_LD,  d, 0, o, s)
#define bpf_ld4i(d, s, o)  bpf_ins(BPF_MEM |BPF_4|BPF_LD,  d, 0, o, s)
#define bpf_ld8i(d, s, o)  bpf_ins(BPF_MEM |BPF_8|BPF_LD,  d, 0, o, s)
#ifdef BPF_SMEM
#define bpf_sld1(d, s, o)  bpf_ins(BPF_SMEM|BPF_1|BPF_LDX, d, s, o, 0)
#define bpf_sld2(d, s, o)  bpf_ins(BPF_SMEM|BPF_2|BPF_LDX, d, s, o, 0)
#define bpf_sld4(d, s, o)  bpf_ins(BPF_SMEM|BPF_4|BPF_LDX, d, s, o, 0)
#define bpf_sld1i(d, s, o) bpf_ins(BPF_SMEM|BPF_1|BPF_LD,  d, 0, o, s)
#define bpf_sld2i(d, s, o) bpf_ins(BPF_SMEM|BPF_2|BPF_LD,  d, 0, o, s)
#define bpf_sld4i(d, s, o) bpf_ins(BPF_SMEM|BPF_4|BPF_LD,  d, 0, o, s)
#endif

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

// 4 ins
#define bpf_ret_call(name, want, ret) \
    bpf_call(name), \
    bpf_jeq8i(bpf_r0, want, 2), \
    bpf_return(ret)

// 9 ins
#define bpf_skb_load(pos, off, len, ret) \
    bpf_mov8(bpf_r1, bpf_r9), \
    bpf_mov8i(bpf_r2, off), \
    bpf_mov8(bpf_r3, bpf_fp), \
    bpf_add8i(bpf_r3, pos), \
    bpf_mov8i(bpf_r4, len), \
    bpf_ret_call(skb_load_bytes, 0, ret)

// 9 ins
#define bpf_map_push(map, pos, ret) \
    bpf_imm8_map_ld(bpf_r1, map), \
    bpf_mov8(bpf_r2, bpf_fp), \
    bpf_add8i(bpf_r2, pos), \
    bpf_mov8i(bpf_r3, BPF_ANY), \
    bpf_ret_call(map_push_elem, 0, ret)

// 6 ins
#define _bpf_stack_zero(n, s) \
    bpf_mov8i(bpf_r2, n), \
    bpf_mov8(bpf_r1, bpf_fp), \
    bpf_add8i(bpf_r1, -s), \
    bpf_st##s##i(bpf_r1, 0, 0), \
    bpf_add8i(bpf_r2, -1), \
    bpf_jsgt8i(bpf_r2, 0, -4)
#define bpf_stack_zero8(n) _bpf_stack_zero(n, 8)
#define bpf_stack_zero4(n) _bpf_stack_zero(n, 4)
#define bpf_stack_zero2(n) _bpf_stack_zero(n, 2)
#define bpf_stack_zero(n)  _bpf_stack_zero(n, 1)

#define eth_proto_off offsetof(struct ethhdr, h_proto)
#define ip_len_off (ETH_HLEN + offsetof(struct iphdr, tot_len))
#define ptr_to_u64(p) (__u64)(p)

void bpf_init(void);
int bpf_is_running(void);
void bpf_print(struct bpf_insn*, size_t);
int bpf_map_create(int*, __u32, __u32, __u32, __u32);
int bpf_map_lookup(__u32, void*, void*);
int bpf_map_pop(__u32, void*);
int bpf_prog_load(int*, __u32, struct bpf_insn*, __u32, char*, uint32_t);
int if_attach(int*, char*, int);
void eth_ip_addr(char*, char*, struct ethhdr*);
char* eth_proto_name(uint16_t);
char* ip_proto_name(uint8_t);
int file_write(int, void*, size_t);
int pcap_open(int*, char*);
int pcap_write(int, void*, uint32_t);

#endif
