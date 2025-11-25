#ifndef ARP_MONITOR_H
#define ARP_MONITOR_H

#include <stdint.h>

/* ARP 操作类型统计（与 eBPF 程序中的结构一致） */
struct arp_stats {
    uint64_t arp_request;   /* ARP 请求 */
    uint64_t arp_reply;     /* ARP 应答 */
    uint64_t rarp_request;  /* RARP 请求 */
    uint64_t rarp_reply;    /* RARP 应答 */
    uint64_t total_packets; /* 总 ARP 包数 */
};

/* ARP 事件记录 */
struct arp_event {
    uint32_t src_ip;        /* 源 IP 地址 */
    uint32_t dst_ip;        /* 目标 IP 地址 */
    uint8_t src_mac[6];     /* 源 MAC 地址 */
    uint8_t dst_mac[6];     /* 目标 MAC 地址 */
    uint16_t opcode;        /* ARP 操作码 */
    uint64_t timestamp;     /* 时间戳 */
};

/* Netlink ARP 表事件类型 */
enum arp_table_event {
    ARP_TABLE_ADD,          /* 添加 ARP 条目 */
    ARP_TABLE_DELETE,       /* 删除 ARP 条目 */
    ARP_TABLE_UPDATE,       /* 更新 ARP 条目 */
    ARP_TABLE_QUERY         /* 查询 ARP 条目 */
};

/* ARP 表条目信息 */
struct arp_table_entry {
    uint32_t ip_addr;       /* IP 地址 */
    uint8_t mac_addr[6];    /* MAC 地址 */
    char dev[16];           /* 网络接口名 */
    uint16_t state;         /* ARP 状态 */
    enum arp_table_event event_type; /* 事件类型 */
};

#endif /* ARP_MONITOR_H */
