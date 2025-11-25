# Network Monitor - 开发文档

本文档提供详细的输出说明、故障排查指南和扩展开发指引。

## 📊 输出说明

### ARP 数据包事件

当网络接口接收到 ARP 数据包时，程序会实时显示：

```
[ARP] REQUEST: <源IP> (<源MAC>) -> <目标IP> (<目标MAC>)
[ARP] REPLY: <源IP> (<源MAC>) -> <目标IP> (<目标MAC>)
```

**示例**:
```
[ARP] REQUEST: 192.168.1.100 (aa:bb:cc:dd:ee:ff) -> 192.168.1.1 (00:00:00:00:00:00)
[ARP] REPLY: 192.168.1.1 (11:22:33:44:55:66) -> 192.168.1.100 (aa:bb:cc:dd:ee:ff)
```

**说明**:
- `REQUEST`: 主机正在查询某个 IP 地址对应的 MAC 地址
- `REPLY`: 响应 ARP 请求，提供 IP→MAC 映射
- 目标 MAC 为全零表示广播查询

### ARP 表变化

当系统 ARP 表发生变化时，通过 Netlink 捕获并显示：

```
[ARP TABLE] <操作>: <IP> -> <MAC> (dev: <接口>, state: <状态>)
```

**示例**:
```
[ARP TABLE] ADD/UPDATE: 192.168.1.50 -> 77:88:99:aa:bb:cc (dev: eth0, state: REACHABLE)
[ARP TABLE] DELETE: 192.168.1.200 -> ff:ee:dd:cc:bb:aa (dev: eth0, state: FAILED)
```

#### 操作类型

| 操作 | 说明 |
|------|------|
| **ADD/UPDATE** | 添加新的 ARP 条目或更新现有条目 |
| **DELETE** | 从 ARP 表中删除条目 |

#### ARP 状态详解

| 状态 | 说明 | 含义 |
|------|------|------|
| **INCOMPLETE** | 正在解析 | ARP 请求已发送，等待响应 |
| **REACHABLE** | 可达且有效 | 条目有效，主机可达 |
| **STALE** | 已过期但可用 | 条目超时，但仍可使用 |
| **DELAY** | 正在验证可达性 | 即将进入 PROBE 状态 |
| **PROBE** | 发送探测中 | 正在发送单播 ARP 探测 |
| **FAILED** | 解析失败 | ARP 解析失败，主机不可达 |
| **NOARP** | 不需要 ARP | 接口不需要 ARP（如 loopback）|
| **PERMANENT** | 永久条目 | 静态配置的永久 ARP 条目 |

### 统计信息

每 10 秒自动显示一次综合统计：

```
╔════════════════════════════════════════════╗
║       Network Monitor Statistics          ║
╠════════════════════════════════════════════╣
║ Total Packets:         15432              ║
╠════════════════════════════════════════════╣
║ ARP Statistics:                           ║
║   Total ARP Packets:   256                ║
║   ARP Requests:        128                ║
║   ARP Replies:         128                ║
║   RARP Requests:       0                  ║
║   RARP Replies:        0                  ║
╚════════════════════════════════════════════╝
```

**字段说明**:
- **Total Packets**: 网络接口接收的所有数据包总数
- **Total ARP Packets**: ARP 协议数据包总数
- **ARP Requests**: ARP 请求数量
- **ARP Replies**: ARP 应答数量
- **RARP Requests/Replies**: 反向 ARP 数据包（较少使用）

## 🔧 故障排查

### 1. 权限错误

**错误信息**:
```
Error: Failed to attach XDP program: Operation not permitted
```

**原因**: 附加 XDP 程序到网络接口需要 root 权限

**解决方案**:
```bash
# 使用 sudo 运行
sudo ./netmon eth0

# 或者添加 capabilities（不推荐）
sudo setcap cap_net_admin,cap_bpf+ep ./netmon
```

### 2. 接口不存在

**错误信息**:
```
Error: Failed to get interface index: No such device
```

**原因**: 指定的网络接口不存在或名称错误

**解决方案**:
```bash
# 查看可用的网络接口
ip link show

# 或使用
ifconfig -a

# 常见的接口名称
# - eth0, eth1: 以太网接口
# - wlan0, wlan1: 无线网接口
# - ens33, ens34: 新命名规范的以太网接口
# - lo: 回环接口（可用于测试）
```

### 3. XDP 不支持

**错误信息**:
```
Error: Failed to attach XDP program
```

**可能原因**:
1. 网卡驱动不支持 XDP
2. 内核版本过低
3. 接口已有 XDP 程序附加

**解决方案**:

**检查内核版本**:
```bash
uname -r
# 需要 >= 4.18，推荐 5.10+
```

**检查网卡驱动**:
```bash
# 查看驱动信息
ethtool -i eth0

# 支持 XDP 的常见驱动
# - ixgbe (Intel 10GbE)
# - i40e (Intel 40GbE)
# - mlx5 (Mellanox)
# - virtio_net (虚拟机)
```

**尝试使用回环接口测试**:
```bash
sudo ./netmon lo
```

**检查是否有其他 XDP 程序**:
```bash
ip link show eth0 | grep xdp
```

**使用 SKB 模式（通用模式，性能较低）**:
修改代码中的标志位（在开发时）：
```c
// 将 XDP_FLAGS_UPDATE_IF_NOEXIST 改为 XDP_FLAGS_SKB_MODE
```

### 4. 编译错误

**错误信息**:
```
fatal error: linux/bpf.h: No such file or directory
```

**原因**: 缺少内核头文件或 libbpf 开发包

**解决方案**:

**Ubuntu/Debian**:
```bash
sudo apt-get update
sudo apt-get install linux-headers-$(uname -r) libbpf-dev libelf-dev clang llvm
```

**CentOS/RHEL**:
```bash
sudo yum install kernel-devel libbpf-devel elfutils-libelf-devel clang llvm
```

**验证安装**:
```bash
# 检查头文件
ls /usr/include/linux/bpf.h

# 检查 libbpf
pkg-config --modversion libbpf
```

### 5. Netlink 套接字创建失败

**警告信息**:
```
Warning: Failed to create netlink socket
```

**影响**:
- 程序继续运行
- ARP 表监控功能被禁用
- 只有 XDP ARP 数据包监控可用

**原因**:
1. 权限不足
2. 内核不支持 Netlink
3. 达到套接字限制

**解决方案**:
```bash
# 1. 确保使用 sudo
sudo ./netmon eth0

# 2. 检查 Netlink 支持
cat /proc/net/netlink

# 3. 检查资源限制
ulimit -n  # 文件描述符限制
```

### 6. 编译警告

**警告信息**:
```
warning: format '%llu' expects argument of type 'long long unsigned int'
```

**影响**: 通常不影响功能，但建议修复

**解决方案**: 已在代码中使用 `(unsigned long)` 类型转换

### 7. Ring Buffer 相关错误

**错误信息**:
```
Error: Failed to create ring buffer
```

**原因**: 内存不足或内核不支持 BPF_MAP_TYPE_RINGBUF

**解决方案**:
```bash
# 检查内核版本（Ring Buffer 需要 >= 5.8）
uname -r

# 检查可用内存
free -h

# 如果内核版本不够，考虑使用 perf buffer 替代
```

## 🛠️ 扩展开发

### 修改统计间隔

在 `src/main.c` 中修改统计显示间隔：

```c
/* 每 10 秒显示一次统计信息 */
time_t now = time(NULL);
if (now - last_stats_time >= 10) {  // 改为其他秒数，如 5 或 30
    display_statistics(packet_map_fd, arp_stats_map_fd);
    last_stats_time = now;
}
```

### 添加协议监控

在 `src/monitor.bpf.c` 的 XDP 程序中添加其他协议的监控：

```c
/* XDP 程序：同时监控所有数据包和 ARP */
SEC("xdp")
int xdp_network_monitor(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // ... 现有代码 ...

    /* 添加 IPv4 监控 */
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(struct ethhdr);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        // 处理 IPv4 数据包
        // 可以统计 TCP、UDP、ICMP 等
    }

    /* 添加 IPv6 监控 */
    if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        // 处理 IPv6 数据包
    }

    return XDP_PASS;
}
```

### 自定义输出格式

修改 `src/main.c` 中的 `display_statistics()` 函数：

```c
void display_statistics(int packet_map_fd, int arp_map_fd)
{
    uint32_t key = 0;
    uint64_t packet_count = 0;
    struct arp_stats arp_stats;

    // 自定义输出格式
    printf("\n=== Statistics ===\n");

    if (bpf_map_lookup_elem(packet_map_fd, &key, &packet_count) == 0) {
        printf("Packets: %lu\n", (unsigned long)packet_count);
    }

    if (bpf_map_lookup_elem(arp_map_fd, &key, &arp_stats) == 0) {
        printf("ARP: %lu (Req: %lu, Rep: %lu)\n",
               (unsigned long)arp_stats.total_packets,
               (unsigned long)arp_stats.arp_request,
               (unsigned long)arp_stats.arp_reply);
    }

    printf("==================\n");
}
```

### 添加过滤规则

在 XDP 程序中添加 IP/MAC 地址过滤：

```c
/* 只监控特定 IP 的 ARP */
if (event->src_ip == bpf_htonl(0xC0A80101)) {  // 192.168.1.1
    // 只记录这个 IP 的 ARP
    bpf_ringbuf_submit(event, 0);
} else {
    bpf_ringbuf_discard(event, 0);
}

/* 过滤特定 MAC 地址 */
__u8 target_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
bool match = true;
#pragma unroll
for (int i = 0; i < 6; i++) {
    if (event->src_mac[i] != target_mac[i]) {
        match = false;
        break;
    }
}
if (match) {
    // 处理匹配的 MAC
}
```

### 添加新的 BPF Map

在 `src/monitor.bpf.c` 中定义新的 Map：

```c
/* 按源 IP 统计 ARP 请求 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);    // IP 地址
    __type(value, __u64);  // 计数
} ip_arp_count SEC(".maps");

// 在 XDP 程序中使用
__u64 *count = bpf_map_lookup_elem(&ip_arp_count, &event->src_ip);
if (count) {
    __sync_fetch_and_add(count, 1);
} else {
    __u64 init_count = 1;
    bpf_map_update_elem(&ip_arp_count, &event->src_ip, &init_count, BPF_ANY);
}
```

### 调试技巧

**使能 libbpf 日志**:
```c
// 在 main.c 中修改
libbpf_set_print(libbpf_print_fn);  // 替换 NULL

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}
```

**使用 bpf_printk 调试 eBPF 程序**:
```c
// 在 monitor.bpf.c 中添加
bpf_printk("ARP packet from IP: %x\n", event->src_ip);

// 在终端中查看输出
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

**验证 BPF Map**:
```bash
# 列出所有 BPF maps
sudo bpftool map list

# 查看 map 内容
sudo bpftool map dump id <map_id>
```

## 🧪 测试建议

### 单元测试

创建测试脚本生成 ARP 流量：

```bash
#!/bin/bash
# test_arp.sh - 生成 ARP 流量用于测试

# 发送 ARP 请求
arping -c 5 -I eth0 192.168.1.1

# 清除 ARP 缓存（观察 DELETE 事件）
sudo ip neigh flush dev eth0

# 重新触发 ARP 解析
ping -c 1 192.168.1.1
```

### 性能测试

```bash
# 使用 pktgen 生成高速数据包
# 观察统计信息的更新速度

# 或使用 iperf3 生成流量
iperf3 -s  # 服务器
iperf3 -c <server_ip> -t 60  # 客户端
```

### 压力测试

```bash
# 同时监控多个接口（需要多个程序实例）
sudo ./netmon eth0 &
sudo ./netmon wlan0 &

# 观察系统资源占用
top -p $(pgrep netmon)
```

## 📖 参考资源

### eBPF/XDP 学习资源

- [eBPF 官方文档](https://ebpf.io/)
- [XDP 教程](https://github.com/xdp-project/xdp-tutorial)
- [Linux XDP 介绍](https://www.iovisor.org/technology/xdp)
- [Cilium eBPF 指南](https://docs.cilium.io/en/latest/bpf/)

### BPF 开发工具

- [bpftool](https://github.com/libbpf/bpftool) - BPF 调试工具
- [libbpf](https://github.com/libbpf/libbpf) - BPF 用户空间库
- [bpftrace](https://github.com/iovisor/bpftrace) - 高级追踪工具

### Netlink 协议

- [Netlink 协议手册](https://man7.org/linux/man-pages/man7/netlink.7.html)
- [rtnetlink 手册](https://man7.org/linux/man-pages/man7/rtnetlink.7.html)

### 网络协议

- [ARP 协议 RFC 826](https://datatracker.ietf.org/doc/html/rfc826)
- [以太网帧格式](https://en.wikipedia.org/wiki/Ethernet_frame)

## 🔍 代码审查清单

在提交代码前，请检查：

- [ ] 所有 BPF 程序都有适当的边界检查
- [ ] Ring Buffer 事件正确提交或丢弃
- [ ] 使用原子操作更新共享计数器
- [ ] 正确处理所有错误情况
- [ ] 资源正确释放（XDP detach、close sockets）
- [ ] 编译无警告
- [ ] 代码符合项目风格
- [ ] 添加了必要的注释

## 💡 贡献指南

欢迎贡献！请遵循以下步骤：

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

### 代码风格

- 使用 4 空格缩进
- 变量名使用下划线命名法
- 函数名使用动词开头
- 添加必要的注释
- 保持函数简短（< 50 行）

---

有问题或建议？请提交 [Issue](https://github.com/yourrepo/issues)！
