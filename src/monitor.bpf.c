#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* 全局数据包计数器 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} packet_count SEC(".maps");

/* ARP 操作类型统计 */
struct arp_stats {
    __u64 arp_request;   /* ARP 请求 */
    __u64 arp_reply;     /* ARP 应答 */
    __u64 rarp_request;  /* RARP 请求 */
    __u64 rarp_reply;    /* RARP 应答 */
    __u64 total_packets; /* 总 ARP 包数 */
};

/* 定义一个 eBPF Map 用于存储 ARP 统计信息 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct arp_stats);
} arp_statistics SEC(".maps");

/* ARP 事件记录（最近的 ARP 事件） */
struct arp_event {
    __u32 src_ip;        /* 源 IP 地址 */
    __u32 dst_ip;        /* 目标 IP 地址 */
    __u8 src_mac[6];     /* 源 MAC 地址 */
    __u8 dst_mac[6];     /* 目标 MAC 地址 */
    __u16 opcode;        /* ARP 操作码 */
    __u64 timestamp;     /* 时间戳 */
};

/* Ring buffer 用于传递 ARP 事件到用户空间 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256KB */
} arp_events SEC(".maps");

/* 整合的 XDP 程序：同时监控所有数据包和 ARP */
SEC("xdp")
int xdp_network_monitor(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u32 key = 0;
    __u64 *count;

    /* 检查以太网头部是否完整 */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    /* 1. 数据包计数 - 统计所有数据包 */
    count = bpf_map_lookup_elem(&packet_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    /* 2. ARP 监控 - 只处理 ARP 数据包 */
    if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
        struct arphdr *arp;
        struct arp_event *event;
        struct arp_stats *stats;

        /* 检查 ARP 头部是否完整 */
        arp = data + sizeof(struct ethhdr);
        if ((void *)(arp + 1) > data_end)
            return XDP_PASS;

        /* 查找统计 map */
        stats = bpf_map_lookup_elem(&arp_statistics, &key);
        if (!stats)
            return XDP_PASS;

        /* 更新统计信息 */
        __sync_fetch_and_add(&stats->total_packets, 1);

        __u16 opcode = bpf_ntohs(arp->ar_op);
        switch (opcode) {
            case ARPOP_REQUEST:
                __sync_fetch_and_add(&stats->arp_request, 1);
                break;
            case ARPOP_REPLY:
                __sync_fetch_and_add(&stats->arp_reply, 1);
                break;
            case ARPOP_RREQUEST:
                __sync_fetch_and_add(&stats->rarp_request, 1);
                break;
            case ARPOP_RREPLY:
                __sync_fetch_and_add(&stats->rarp_reply, 1);
                break;
        }

        /* 为 ARP 事件分配 ring buffer 空间 */
        event = bpf_ringbuf_reserve(&arp_events, sizeof(struct arp_event), 0);
        if (!event)
            return XDP_PASS;

        /* 记录 ARP 事件详情（需要额外边界检查）*/
        void *arp_data = (void *)arp + sizeof(struct arphdr);

        /* 检查 ARP 负载是否完整（硬件地址长度 + 协议地址长度） */
        if (arp_data + 2 * (arp->ar_hln + arp->ar_pln) > data_end) {
            bpf_ringbuf_discard(event, 0);
            return XDP_PASS;
        }

        event->opcode = opcode;
        event->timestamp = bpf_ktime_get_ns();

        /* 解析 ARP 数据（仅支持以太网和 IPv4） */
        if (arp->ar_hrd == bpf_htons(ARPHRD_ETHER) &&
            arp->ar_pro == bpf_htons(ETH_P_IP) &&
            arp->ar_hln == 6 && arp->ar_pln == 4) {

            __u8 *ptr = arp_data;

            /* 源 MAC */
            #pragma unroll
            for (int i = 0; i < 6; i++) {
                if (ptr + i >= (__u8 *)data_end) {
                    bpf_ringbuf_discard(event, 0);
                    return XDP_PASS;
                }
                event->src_mac[i] = ptr[i];
            }
            ptr += 6;

            /* 源 IP */
            if (ptr + 4 > (__u8 *)data_end) {
                bpf_ringbuf_discard(event, 0);
                return XDP_PASS;
            }
            event->src_ip = *(__u32 *)ptr;
            ptr += 4;

            /* 目标 MAC */
            #pragma unroll
            for (int i = 0; i < 6; i++) {
                if (ptr + i >= (__u8 *)data_end) {
                    bpf_ringbuf_discard(event, 0);
                    return XDP_PASS;
                }
                event->dst_mac[i] = ptr[i];
            }
            ptr += 6;

            /* 目标 IP */
            if (ptr + 4 > (__u8 *)data_end) {
                bpf_ringbuf_discard(event, 0);
                return XDP_PASS;
            }
            event->dst_ip = *(__u32 *)ptr;
        }

        /* 提交事件到 ring buffer */
        bpf_ringbuf_submit(event, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
