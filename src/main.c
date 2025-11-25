#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include "../include/arp_monitor.h"

static volatile sig_atomic_t keep_running = 1;

void sig_handler(int signo)
{
    keep_running = 0;
}

/* 将 MAC 地址转换为字符串 */
void mac_to_str(const uint8_t *mac, char *str)
{
    sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* 将 IP 地址转换为字符串 */
void ip_to_str(uint32_t ip, char *str)
{
    struct in_addr addr;
    addr.s_addr = ip;
    strcpy(str, inet_ntoa(addr));
}

/* 获取 ARP 操作类型字符串 */
const char* get_arp_opcode_str(uint16_t opcode)
{
    switch (opcode) {
        case 1: return "REQUEST";
        case 2: return "REPLY";
        case 3: return "RARP-REQUEST";
        case 4: return "RARP-REPLY";
        default: return "UNKNOWN";
    }
}

/* 获取 ARP 状态字符串 */
const char* get_arp_state_str(uint16_t state)
{
    switch (state) {
        case NUD_INCOMPLETE: return "INCOMPLETE";
        case NUD_REACHABLE: return "REACHABLE";
        case NUD_STALE: return "STALE";
        case NUD_DELAY: return "DELAY";
        case NUD_PROBE: return "PROBE";
        case NUD_FAILED: return "FAILED";
        case NUD_NOARP: return "NOARP";
        case NUD_PERMANENT: return "PERMANENT";
        default: return "UNKNOWN";
    }
}

/* 处理 ring buffer 中的 ARP 事件 */
int handle_arp_event(void *ctx, void *data, size_t data_sz)
{
    struct arp_event *event = data;
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    char src_mac_str[18];
    char dst_mac_str[18];

    ip_to_str(event->src_ip, src_ip_str);
    ip_to_str(event->dst_ip, dst_ip_str);
    mac_to_str(event->src_mac, src_mac_str);
    mac_to_str(event->dst_mac, dst_mac_str);

    printf("[ARP] %s: %s (%s) -> %s (%s)\n",
           get_arp_opcode_str(event->opcode),
           src_ip_str, src_mac_str,
           dst_ip_str, dst_mac_str);

    return 0;
}

/* 创建 Netlink 套接字用于监听 ARP 表变化 */
int create_netlink_socket(void)
{
    int sock;
    struct sockaddr_nl addr;

    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        fprintf(stderr, "Warning: Failed to create netlink socket: %s\n", strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_NEIGH; /* 订阅邻居表（ARP）变化 */

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Warning: Failed to bind netlink socket: %s\n", strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

/* 处理 Netlink ARP 表事件 */
void handle_netlink_arp(int sock)
{
    char buf[4096];
    struct nlmsghdr *nlh;
    struct ndmsg *ndm;
    struct rtattr *rta;
    int len, attrlen;

    len = recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
    if (len < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            fprintf(stderr, "Error: Netlink recv failed: %s\n", strerror(errno));
        return;
    }

    for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
        if (nlh->nlmsg_type == NLMSG_DONE)
            break;

        if (nlh->nlmsg_type == NLMSG_ERROR) {
            fprintf(stderr, "Error: Netlink message error\n");
            continue;
        }

        /* 只处理邻居表消息 */
        if (nlh->nlmsg_type != RTM_NEWNEIGH && nlh->nlmsg_type != RTM_DELNEIGH)
            continue;

        ndm = (struct ndmsg *)NLMSG_DATA(nlh);

        /* 只处理 ARP（IPv4）条目 */
        if (ndm->ndm_family != AF_INET)
            continue;

        char ip_str[INET_ADDRSTRLEN] = {0};
        char mac_str[18] = {0};
        char ifname[IF_NAMESIZE] = {0};
        uint32_t ip_addr = 0;
        uint8_t mac_addr[6] = {0};

        /* 获取接口名 */
        if_indextoname(ndm->ndm_ifindex, ifname);

        /* 解析属性 */
        rta = (struct rtattr *)((char *)ndm + NLMSG_ALIGN(sizeof(struct ndmsg)));
        attrlen = nlh->nlmsg_len - NLMSG_ALIGN(sizeof(struct nlmsghdr)) - NLMSG_ALIGN(sizeof(struct ndmsg));

        for (; RTA_OK(rta, attrlen); rta = RTA_NEXT(rta, attrlen)) {
            switch (rta->rta_type) {
                case NDA_DST:
                    ip_addr = *(uint32_t *)RTA_DATA(rta);
                    ip_to_str(ip_addr, ip_str);
                    break;
                case NDA_LLADDR:
                    memcpy(mac_addr, RTA_DATA(rta), 6);
                    mac_to_str(mac_addr, mac_str);
                    break;
            }
        }

        /* 打印 ARP 表事件 */
        const char *event_str = (nlh->nlmsg_type == RTM_NEWNEIGH) ? "ADD/UPDATE" : "DELETE";
        printf("[ARP TABLE] %s: %s -> %s (dev: %s, state: %s)\n",
               event_str, ip_str, mac_str, ifname, get_arp_state_str(ndm->ndm_state));
    }
}

/* 显示综合统计信息 */
void display_statistics(int packet_map_fd, int arp_map_fd)
{
    uint32_t key = 0;
    uint64_t packet_count = 0;
    struct arp_stats arp_stats;

    printf("\n");
    printf("╔════════════════════════════════════════════╗\n");
    printf("║       Network Monitor Statistics          ║\n");
    printf("╠════════════════════════════════════════════╣\n");

    /* 读取总数据包计数 */
    if (bpf_map_lookup_elem(packet_map_fd, &key, &packet_count) == 0) {
        printf("║ Total Packets:         %-18lu ║\n", (unsigned long)packet_count);
    } else {
        printf("║ Total Packets:         N/A                ║\n");
    }

    printf("╠════════════════════════════════════════════╣\n");

    /* 读取 ARP 统计 */
    if (bpf_map_lookup_elem(arp_map_fd, &key, &arp_stats) == 0) {
        printf("║ ARP Statistics:                           ║\n");
        printf("║   Total ARP Packets:   %-18lu ║\n", (unsigned long)arp_stats.total_packets);
        printf("║   ARP Requests:        %-18lu ║\n", (unsigned long)arp_stats.arp_request);
        printf("║   ARP Replies:         %-18lu ║\n", (unsigned long)arp_stats.arp_reply);
        printf("║   RARP Requests:       %-18lu ║\n", (unsigned long)arp_stats.rarp_request);
        printf("║   RARP Replies:        %-18lu ║\n", (unsigned long)arp_stats.rarp_reply);
    } else {
        printf("║ ARP Statistics:        N/A                ║\n");
    }

    printf("╚════════════════════════════════════════════╝\n");
    printf("\n");
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct ring_buffer *rb = NULL;
    int prog_fd, packet_map_fd, arp_stats_map_fd, arp_events_map_fd, netlink_sock;
    int ifindex;
    int err;

    printf("╔════════════════════════════════════════════════════════╗\n");
    printf("║   Integrated Network Monitor - Packet & ARP Tracker   ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n\n");

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <network_interface>\n", argv[0]);
        fprintf(stderr, "Example: %s eth0\n", argv[0]);
        return 1;
    }

    /* 获取网络接口索引 */
    ifindex = if_nametoindex(argv[1]);
    if (ifindex == 0) {
        fprintf(stderr, "Error: Failed to get interface index for %s: %s\n",
                argv[1], strerror(errno));
        return 1;
    }

    /* 设置 libbpf 日志级别 */
    libbpf_set_print(NULL);

    /* 打开并加载 eBPF 对象文件 */
    obj = bpf_object__open_file("src/monitor.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error: Failed to open BPF object file\n");
        return 1;
    }

    /* 加载 eBPF 程序到内核 */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Error: Failed to load BPF object: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    /* 获取 eBPF 程序 */
    prog = bpf_object__find_program_by_name(obj, "xdp_network_monitor");
    if (!prog) {
        fprintf(stderr, "Error: Failed to find BPF program\n");
        bpf_object__close(obj);
        return 1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Error: Failed to get program FD\n");
        bpf_object__close(obj);
        return 1;
    }

    /* 将 XDP 程序附加到网络接口 */
    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    if (err) {
        fprintf(stderr, "Error: Failed to attach XDP program to %s: %s\n",
                argv[1], strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    printf("✓ Successfully attached XDP program to %s\n", argv[1]);

    /* 获取 map 文件描述符 */
    packet_map_fd = bpf_object__find_map_fd_by_name(obj, "packet_count");
    if (packet_map_fd < 0) {
        fprintf(stderr, "Error: Failed to find packet_count map\n");
        bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
        bpf_object__close(obj);
        return 1;
    }

    arp_stats_map_fd = bpf_object__find_map_fd_by_name(obj, "arp_statistics");
    if (arp_stats_map_fd < 0) {
        fprintf(stderr, "Error: Failed to find arp_statistics map\n");
        bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
        bpf_object__close(obj);
        return 1;
    }

    arp_events_map_fd = bpf_object__find_map_fd_by_name(obj, "arp_events");
    if (arp_events_map_fd < 0) {
        fprintf(stderr, "Error: Failed to find arp_events map\n");
        bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
        bpf_object__close(obj);
        return 1;
    }

    /* 创建 ring buffer 用于接收 ARP 事件 */
    rb = ring_buffer__new(arp_events_map_fd, handle_arp_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Error: Failed to create ring buffer\n");
        bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
        bpf_object__close(obj);
        return 1;
    }

    /* 创建 Netlink 套接字监听 ARP 表变化 */
    netlink_sock = create_netlink_socket();
    if (netlink_sock < 0) {
        printf("⚠ Warning: ARP table monitoring disabled (Netlink socket creation failed)\n");
    }

    printf("✓ Monitoring enabled:\n");
    printf("  • Packet counter: All packets\n");
    printf("  • ARP packets: Requests/Replies via XDP\n");
    if (netlink_sock >= 0) {
        printf("  • ARP table: Add/Update/Delete via Netlink\n");
    }
    printf("\nPress Ctrl+C to stop\n");
    printf("════════════════════════════════════════════════════════\n\n");

    /* 设置信号处理器 */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* 主循环：监听 ARP 事件和 Netlink 消息 */
    time_t last_stats_time = time(NULL);
    while (keep_running) {
        fd_set readfds;
        struct timeval tv;
        int maxfd;

        FD_ZERO(&readfds);
        maxfd = -1;

        /* 添加 Netlink socket 到 select */
        if (netlink_sock >= 0) {
            FD_SET(netlink_sock, &readfds);
            if (netlink_sock > maxfd)
                maxfd = netlink_sock;
        }

        /* 设置超时 */
        tv.tv_sec = 0;
        tv.tv_usec = 100000; /* 100ms */

        int ret = select(maxfd + 1, &readfds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "Error: select failed: %s\n", strerror(errno));
            break;
        }

        /* 处理 Netlink ARP 表事件 */
        if (netlink_sock >= 0 && FD_ISSET(netlink_sock, &readfds)) {
            handle_netlink_arp(netlink_sock);
        }

        /* 轮询 ring buffer 中的 XDP ARP 事件 */
        err = ring_buffer__poll(rb, 0);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error: Failed to poll ring buffer: %s\n", strerror(-err));
            break;
        }

        /* 每 10 秒显示一次统计信息 */
        time_t now = time(NULL);
        if (now - last_stats_time >= 10) {
            display_statistics(packet_map_fd, arp_stats_map_fd);
            last_stats_time = now;
        }
    }

    printf("\n\n════════════════════════════════════════════════════════\n");
    printf("Shutting down...\n");

    /* 显示最终统计 */
    display_statistics(packet_map_fd, arp_stats_map_fd);

    /* 清理 */
    if (netlink_sock >= 0)
        close(netlink_sock);
    if (rb)
        ring_buffer__free(rb);
    bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    bpf_object__close(obj);

    printf("✓ Program terminated successfully\n");
    return 0;
}
