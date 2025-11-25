# Network Monitor - eBPF 网络监控工具

一个基于 eBPF/XDP 和 Netlink 的高性能网络监控工具，提供实时数据包统计和 ARP 协议监控。

## ✨ 核心功能

- **📊 全局数据包计数** - 实时统计网络接口上的所有数据包
- **🔍 ARP 数据包监控** - 捕获和分析 ARP Request/Reply 数据包
- **📡 ARP 表监控** - 跟踪系统 ARP 表的增删改操作
- **📈 实时统计展示** - 每 10 秒显示美观的综合统计信息


## ⚙️ 系统要求

- **Linux 内核**: >= 4.18 (推荐 5.10+)
- **eBPF 支持**: 内核需启用 BPF 和 XDP
- **开发工具**:

```bash
# Ubuntu/Debian
sudo apt-get install clang llvm gcc libbpf-dev libelf-dev linux-headers-$(uname -r)

# CentOS/RHEL
sudo yum install clang llvm gcc libbpf-devel elfutils-libelf-devel kernel-devel

# Fedora
sudo dnf install clang llvm gcc libbpf-devel elfutils-libelf-devel kernel-devel
```

## 🔨 编译

```bash
# 编译
make

# 查看帮助
make help

# 清理
make clean

# 安装到系统（可选）
sudo make install
```

## 🚀 使用方法

### 基本用法

```bash
# 监控指定网络接口（需要 root 权限）
sudo ./netmon eth0

# 或者监控其他接口
sudo ./netmon wlan0
sudo ./netmon ens33
```

### 运行示例

```
╔════════════════════════════════════════════════════════╗
║   Integrated Network Monitor - Packet & ARP Tracker   ║
╚════════════════════════════════════════════════════════╝

✓ Successfully attached XDP program to eth0
✓ Monitoring enabled:
  • Packet counter: All packets
  • ARP packets: Requests/Replies via XDP
  • ARP table: Add/Update/Delete via Netlink

Press Ctrl+C to stop
════════════════════════════════════════════════════════

[ARP] REQUEST: 192.168.1.100 (aa:bb:cc:dd:ee:ff) -> 192.168.1.1 (00:00:00:00:00:00)
[ARP] REPLY: 192.168.1.1 (11:22:33:44:55:66) -> 192.168.1.100 (aa:bb:cc:dd:ee:ff)
[ARP TABLE] ADD/UPDATE: 192.168.1.50 -> 77:88:99:aa:bb:cc (dev: eth0, state: REACHABLE)

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

### 停止监控

按 `Ctrl+C` 优雅退出，程序会自动：
- 显示最终统计信息
- 分离 XDP 程序
- 关闭 Netlink 套接字
- 释放所有资源

## 🔍 工作原理

### 架构图

```
┌─────────────────────────────────────────────┐
│           User Space (netmon)              │
├─────────────────────────────────────────────┤
│  • Ring Buffer Consumer (ARP events)       │
│  • Netlink Socket (ARP table changes)      │
│  • Statistics Display                      │
└───────────┬─────────────────────────────────┘
            │ bpf syscalls / netlink
            │
┌───────────▼─────────────────────────────────┐
│              Kernel Space                   │
├─────────────────────────────────────────────┤
│  XDP Hook (xdp_network_monitor)            │
│  ├─ Count all packets                      │
│  └─ Parse & record ARP packets             │
│                                             │
│  BPF Maps:                                  │
│  ├─ packet_count (ARRAY)                   │
│  ├─ arp_statistics (ARRAY)                 │
│  └─ arp_events (RINGBUF)                   │
│                                             │
│  Netlink (RTMGRP_NEIGH)                     │
│  └─ ARP table notifications                │
└─────────────────────────────────────────────┘
            │
┌───────────▼─────────────────────────────────┐
│       Network Interface (eth0)             │
│         Incoming Packets                    │
└─────────────────────────────────────────────┘
```

### 技术特性

#### eBPF/XDP 层
- 在网络驱动程序层面拦截数据包
- 使用 XDP (eXpress Data Path) 实现零拷贝、低延迟处理
- 支持数百万 pps 的高性能处理
- 单次遍历同时完成所有监控任务

#### BPF Maps
- **ARRAY**: 存储全局计数器和 ARP 统计信息
- **RINGBUF**: 高效传递 ARP 事件到用户空间

#### Netlink
- 订阅内核 RTMGRP_NEIGH 消息组
- 实时监听 ARP 表的增删改操作
- 显示 ARP 条目状态变化

### 数据流

```
网卡 → XDP Hook → eBPF Program → BPF Maps
                                    ↓
                            Ring Buffer/Netlink
                                    ↓
                            User Space Program → 显示
```

## 🎯 应用场景

### 网络监控
- 实时统计网络流量和数据包速率
- 监控网络活动模式
- 分析网络性能

### 网络调试
- 诊断 ARP 解析问题
- 检测 IP 地址冲突
- 追踪数据包丢失

### 安全监控
- 检测 ARP 欺骗攻击（MAC 地址异常变化）
- 监控非授权设备接入
- 追踪异常 ARP 活动

### 性能分析
- 测量网络吞吐量
- 分析 ARP 缓存行为
- 优化网络配置

## 📚 文档

### 快速开始

本 README 提供了基本的安装和使用指南。

### 详细文档

更详细的信息请参阅：

- **[开发文档](docs/develop.md)** - 包含：
  - 📊 详细的输出说明和格式
  - 🔧 完整的故障排查指南
  - 🛠️ 扩展开发指引和示例代码
  - 🧪 测试建议和调试技巧

### 外部资源

- [eBPF 官方文档](https://ebpf.io/)
- [XDP 教程](https://github.com/xdp-project/xdp-tutorial)
- [libbpf API 文档](https://libbpf.readthedocs.io/)
- [Netlink 协议手册](https://man7.org/linux/man-pages/man7/netlink.7.html)

## 📄 许可证

GPL License - 符合 eBPF 程序的许可证要求

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📝 更新日志

### v1.0.0
- 整合数据包计数和 ARP 监控功能
- 基于 XDP 的高性能数据包处理
- Netlink ARP 表监控
- 美观的实时统计展示
