#include <fcntl.h>
#include <signal.h>
#include <net/if.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/if_packet.h>

#include "./bpf.h"

volatile int _running = 0;

char*
_bpf_print(struct bpf_insn *ins) {
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
    _case3(ALU4) __fallthrough;
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
    _case3(JMP4) __fallthrough;
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
    _case3(ST) __fallthrough;
    _case3(STX) __fallthrough;
    _case3(LD) __fallthrough;
    _case3(LDX)
        switch (BPF_MODE(ins->code)) {
        _case1(IMM);
        _case1(MEM);
        _case1(ATOM);
#ifdef BPF_SMEM
        _case1(SMEM);
#endif
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

    snprintf(buf, sizeof(buf), "[%02x] %4s %s %4s %x %x %8d %8ld",
        ins->code, s1, s2, s3, ins->dst_reg, ins->src_reg,
        (int32_t)ins->off, (int64_t)ins->imm);
    return buf;
}

void
bpf_print(struct bpf_insn *insns, size_t insn_cnt) {
    char buf[128];
    int n;
    snprintf(buf, sizeof(buf), "%ld", insn_cnt);
    n = strlen(buf);
    for (size_t i = 0; i < insn_cnt; i++)
        LOG("%*ld %s\n", n, i, _bpf_print(&insns[i]));
}

int
bpf_map_create(int *map, __u32 map_type, __u32 key_size, __u32 value_size,
    __u32 max_entries) {
    union bpf_attr attr = {0};
    attr.map_type = map_type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = max_entries;
    *map = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    return (*map == -1) ? errno : 0;
}

int
bpf_map_lookup(__u32 map_fd, void *key, void *value) {
    union bpf_attr attr = {0};
    attr.map_fd = map_fd;
    attr.key = ptr_to_u64(key);
    attr.value = ptr_to_u64(value);
    if (syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)) == -1)
        return errno;
    return 0;
}

int
bpf_map_pop(__u32 map_fd, void *value) {
    union bpf_attr attr = {0};
    attr.map_fd = map_fd;
    attr.value = ptr_to_u64(value);
    if (syscall(__NR_bpf, BPF_MAP_LOOKUP_AND_DELETE_ELEM,
        &attr, sizeof(attr)) == -1)
        return errno;
    return 0;
}

int
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
    *prog = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));

    if (dump > 0) {
        LOG("%s\n", log);
        free(log);
    }
    return (*prog == -1) ? errno : 0;
}

int
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

void
addr_pair(struct addr_pair_t *p, int af, void *hdr) {
    ASSERT(af == AF_INET6 || af == AF_INET);
    if (af == AF_INET6) {
        inet_ntop(af, &((struct ipv6hdr*)hdr)->saddr, p->src,
            INET6_ADDRSTRLEN);
        inet_ntop(af, &((struct ipv6hdr*)hdr)->daddr, p->dst,
            INET6_ADDRSTRLEN);
    } else {
        inet_ntop(af, &((struct iphdr*)hdr)->saddr, p->src,
            INET_ADDRSTRLEN);
        inet_ntop(af, &((struct iphdr*)hdr)->daddr, p->dst,
            INET_ADDRSTRLEN);
    }
}

char*
eth_proto_name(uint16_t p) {
    p = ntohs(p);
    switch(p) {
    case ETH_P_IP: return "IP";
    case ETH_P_IPV6: return "IPV6";
    default: return hexstr(p);
    }
}

char*
ip_proto_name(uint8_t p) {
    switch (p) {
#define _case(_p) case IPPROTO_##_p: return #_p;
    _case(IGMP);
    _case(ICMP);
    _case(ICMPV6);
    _case(TCP);
    _case(UDP);
    default: return hexstr(p);
#undef _case
    }
}

struct pcap_file_header {
    uint8_t magic[4];
    uint16_t version_major, version_minor;
    uint32_t thiszone, sigfigs, snaplen, linktype;
};

struct pcap_pkthdr {
    uint32_t sec, usec, caplen, len;
};

int
file_write(int fd, void *p0, size_t size) {
    int ret = 0;
    uint8_t *p = ((uint8_t*)p0);
    ssize_t n;

    while (size > 0) {
        if ((n = write(fd, p, size)) == -1) {
            TRYF(errno == EAGAIN, RETURN(errno, err), "%s\n", strerror(errno));
            break;
        }
        p += n;
        size -= n;
    }

err:
    return ret;
}

int
pcap_open(int *fd, char *fn) {
    int ret = 0;
    struct pcap_file_header h = {0};

    TRY((*fd = open(fn, O_WRONLY|O_CREAT|O_TRUNC, 0644)) > 0,
        RETURN(errno, err));

    // little-endian and microsecond
    h.magic[0] = 0xd4;
    h.magic[1] = 0xc3;
    h.magic[2] = 0xb2;
    h.magic[3] = 0xa1;
    h.version_major = htole16(2);
    h.version_minor = htole16(4);
    h.snaplen = htole32(65535);
    h.linktype = htole32(1); // ethernet
    TRY(!(ret = file_write(*fd, &h, sizeof(h))),);
err:
    return ret;
}

int
pcap_write(int fd, void *p, uint32_t size) {
    int ret = 0;
    struct pcap_pkthdr h = {0};
    struct timeval t;

    TRY(!gettimeofday(&t, NULL), RETURN(errno, err));
    h.sec = htole32(t.tv_sec);
    h.usec = htole32(t.tv_usec);
    h.len = h.caplen = htole32(size);
    TRY(!(ret = file_write(fd, &h, sizeof(h))), goto err);
    TRY(!(ret = file_write(fd, p, size)),);
err:
    return ret;
}

void
_sigint_handler(int sig __unused) {
    _running = 0;
}

void
_bpf_exit(void) {
    LOG("exit\n");
}

void
bpf_init(void) {
    struct sigaction sa = {
        .sa_handler = _sigint_handler,
        .sa_flags = SA_RESTART
    };
    _running = 1;
    sigemptyset(&sa.sa_mask);
    ASSERT(!sigaction(SIGINT, &sa, NULL));
    ASSERT(!atexit(_bpf_exit));
}

int
bpf_is_running(void) {
    return _running;
}
