/*
 * ttl65.bpf.c — tc-clsact egress eBPF program that rewrites IPv4 TTL and
 * IPv6 hop-limit to 65. Designed for Android raw-IP `rmnet*` interfaces,
 * where skb->data starts at L3 (no Ethernet header).
 *
 * Self-contained: no kernel/uapi headers required. Build with:
 *     clang -target bpf -O2 -g -c ttl65.bpf.c -o ttl65.bpf.o
 *
 * Load with:
 *     bpftool prog load ttl65.bpf.o /sys/fs/bpf/ttl65ebpf_prog type classifier
 *     tc qdisc add dev rmnet1 clsact
 *     tc filter add dev rmnet1 egress pref 60650 handle 65 \
 *         bpf direct-action object-pinned /sys/fs/bpf/ttl65ebpf_prog
 */

#define SEC(NAME) __attribute__((section(NAME), used))

typedef unsigned char       __u8;
typedef unsigned short      __u16;
typedef unsigned int        __u32;
typedef unsigned long long  __u64;

/* Trimmed __sk_buff layout from <uapi/linux/bpf.h> — only the fields used. */
struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;     /* __be16 in low bits, zero-extended */
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;
    __u32 data;
    __u32 data_end;
    __u32 napi_id;
};

#define TC_ACT_OK 0

/* BPF helper IDs from include/uapi/linux/bpf.h */
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset,
                                  void *to, __u32 len) = (void *) 26;
static long (*bpf_skb_store_bytes)(void *skb, __u32 offset,
                                   const void *from, __u32 len,
                                   __u64 flags) = (void *) 9;
static long (*bpf_l3_csum_replace)(void *skb, __u32 offset,
                                   __u64 from, __u64 to,
                                   __u64 size) = (void *) 10;

/* Network-byte-order ethertypes on a little-endian host (Android = LE). */
#define BE_ETH_P_IP   0x0008    /* htons(0x0800) */
#define BE_ETH_P_IPV6 0xDD86    /* htons(0x86DD) */

#define IPV4_TTL_OFF   8        /* offsetof(struct iphdr, ttl)        */
#define IPV4_CHECK_OFF 10       /* offsetof(struct iphdr, check)      */
#define IPV6_HL_OFF    7        /* offsetof(struct ipv6hdr, hop_limit)*/

#define TARGET 65

SEC("tc")
int set_ttl_egress(struct __sk_buff *skb)
{
    __u32 proto = skb->protocol;
    __u8  cur;
    __u8  new_ttl = TARGET;

    if (proto == BE_ETH_P_IP) {
        if (bpf_skb_load_bytes(skb, IPV4_TTL_OFF, &cur, 1) < 0)
            return TC_ACT_OK;
        if (cur == TARGET)
            return TC_ACT_OK;
        bpf_l3_csum_replace(skb, IPV4_CHECK_OFF, cur, new_ttl, 2);
        bpf_skb_store_bytes(skb, IPV4_TTL_OFF, &new_ttl, 1, 0);
    } else if (proto == BE_ETH_P_IPV6) {
        if (bpf_skb_load_bytes(skb, IPV6_HL_OFF, &cur, 1) < 0)
            return TC_ACT_OK;
        if (cur == TARGET)
            return TC_ACT_OK;
        bpf_skb_store_bytes(skb, IPV6_HL_OFF, &new_ttl, 1, 0);
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
