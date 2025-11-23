#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

/* 定义一个 eBPF Map 用于存储数据包计数 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} packet_count SEC(".maps");

/* XDP 程序：在网络数据包到达时执行 */
SEC("xdp")
int xdp_packet_counter(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u64 *count;

    /* 查找 map 中的计数器 */
    count = bpf_map_lookup_elem(&packet_count, &key);
    if (count) {
        /* 原子递增计数器 */
        __sync_fetch_and_add(count, 1);
    }

    /* XDP_PASS 表示将数据包继续传递给网络栈 */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
