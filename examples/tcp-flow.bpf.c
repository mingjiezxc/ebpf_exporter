#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"

#define MAX_ENTRIES 8192

#define AF_INET 2
#define AF_INET6 10

#define UPPER_PORT_BOUND 32768

struct ip_key_t {
    u8 saddr[16];
    u8 daddr[16];
    u16 main_port;
    u8 type;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct ip_key_t);
    __type(value, u64);
} tcp_flow_rx_bytes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct ip_key_t);
    __type(value, u64);
} tcp_flow_tx_bytes SEC(".maps");

static int extract_main_port(const struct sock *sk)
{
    u16 sport = sk->__sk_common.skc_num;
    u16 dport = __builtin_bswap16(sk->__sk_common.skc_dport);

    if (sport < dport) {
        if (sport > 30000) {
            return 0;
        }

        return sport;
    }

    if (dport > 30000) {
        return 0;
    }

    return dport;
}

static int trace_event(const struct sock *sk, int size, bool is_tx)
{
    struct ip_key_t key = {};
    key.main_port = extract_main_port(sk);

    if (key.main_port == 0) {
        return 0;
    }

    switch (sk->__sk_common.skc_family) {
    case AF_INET:
        key.type = AF_INET;
        bpf_probe_read_kernel(&key.saddr, sizeof(key.saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&key.daddr, sizeof(key.daddr), &sk->__sk_common.skc_daddr);
    case AF_INET6:
        key.type = AF_INET6;
        bpf_probe_read_kernel(&key.saddr, sizeof(key.saddr), sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&key.daddr, sizeof(key.daddr), sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

    if (is_tx) {
        increment_map(&tcp_flow_tx_bytes, &key, size);
    } else {
        increment_map(&tcp_flow_rx_bytes, &key, size);
    }

    return 0;
}

// 新增：捕获TCP发送消息事件
SEC("fentry/tcp_sendmsg")
int BPF_PROG(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    return trace_event(sk, size, true);
}

SEC("fentry/tcp_cleanup_rbuf")
int BPF_PROG(tcp_cleanup_rbuf, struct sock *sk)
{
    size_t size = sk->sk_rcvbuf;
    return trace_event(sk, size, false);
}

char LICENSE[] SEC("license") = "GPL";