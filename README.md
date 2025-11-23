# Network Monitor - eBPF 网络数据包监控器

这是一个基于 eBPF (extended Berkeley Packet Filter) 的网络数据包监控工具，可以实时统计网络接口接收到的数据包数量。

## 项目架构

```
network-monitor/
├── src/
│   ├── packet_counter.bpf.c    # eBPF 内核态程序
│   └── monitor.c                # 用户态加载和监控程序
├── Makefile                     # 构建脚本
└── README.md                    # 说明文档
```

## 工作原理

1. **eBPF 内核程序** (`packet_counter.bpf.c`):
   - 在网络数据包到达时被触发
   - 使用 eBPF Map 维护一个全局计数器
   - 每接收一个数据包，计数器递增
   - 使用 XDP (eXpress Data Path) 钩子在网络栈最早期拦截数据包

2. **用户态程序** (`monitor.c`):
   - 将 eBPF 程序编译后的字节码加载到内核
   - 将 eBPF 程序附加到指定的网络接口
   - 定期读取 eBPF Map 中的计数器值
   - 实时显示数据包统计信息

## 系统要求

- Linux 内核版本 >= 5.4 (推荐 5.10+)
- 内核需启用 eBPF 和 XDP 支持
- 必需的开发工具和库:
  ```bash
  # Ubuntu/Debian
  sudo apt-get install clang llvm gcc libbpf-dev linux-headers-$(uname -r)

  # CentOS/RHEL
  sudo yum install clang llvm gcc libbpf-devel kernel-devel

  # Fedora
  sudo dnf install clang llvm gcc libbpf-devel kernel-devel
  ```

## 编译

在项目根目录执行:

```bash
make
```

编译成功后会生成:
- `src/packet_counter.bpf.o` - eBPF 字节码
- `network-monitor` - 用户态可执行程序

## 使用方法

### 基本使用

需要 root 权限运行:

```bash
sudo ./network-monitor <网络接口名>
```

示例:

```bash
# 监控 eth0 接口
sudo ./network-monitor eth0

# 监控 lo 环回接口
sudo ./network-monitor lo
```

### 查看可用网络接口

```bash
ip link show
# 或
ifconfig -a
```

### 运行示例

```bash
$ sudo ./network-monitor eth0
Successfully attached XDP program to eth0
Monitoring packets... Press Ctrl+C to stop

Packets received: 12456
```

按 `Ctrl+C` 停止监控，程序会自动清理并分离 eBPF 程序。

## 测试

在另一个终端生成网络流量来测试:

```bash
# 生成流量测试
ping -c 100 8.8.8.8

# 或使用 curl
curl https://www.google.com
```

你会看到 network-monitor 实时更新数据包计数。

## 技术细节

### eBPF Map

程序使用 `BPF_MAP_TYPE_ARRAY` 类型的 Map 存储数据包计数:
- Key: 固定为 0 (只有一个计数器)
- Value: 64位无符号整数 (数据包数量)

### XDP 返回值

程序返回 `XDP_PASS`，表示:
- 数据包被 eBPF 程序处理后继续传递给网络栈
- 不影响正常的网络通信

其他可能的返回值:
- `XDP_DROP` - 丢弃数据包
- `XDP_TX` - 从同一接口发送回去
- `XDP_REDIRECT` - 重定向到其他接口

### 线程安全

计数器使用原子操作 `__sync_fetch_and_add()` 来保证在多核环境下的正确性。

## 清理

```bash
# 清理编译产物
make clean
```

## 故障排查

### 权限错误

```
Error: Failed to attach XDP program: Operation not permitted
```

**解决**: 使用 `sudo` 运行程序

### 接口不存在

```
Error: Failed to get interface index: No such device
```

**解决**: 使用 `ip link show` 检查接口名称是否正确

### 缺少内核头文件

```
fatal error: linux/bpf.h: No such file or directory
```

**解决**: 安装内核头文件
```bash
sudo apt-get install linux-headers-$(uname -r)
```

### libbpf 库缺失

```
/usr/bin/ld: cannot find -lbpf
```

**解决**: 安装 libbpf 开发包
```bash
sudo apt-get install libbpf-dev
```

## 扩展功能建议

基于当前的基础架构，可以扩展以下功能:

1. **协议分析**: 统计 TCP/UDP/ICMP 等不同协议的数据包
2. **流量统计**: 记录数据包大小和总流量
3. **源/目标分析**: 统计不同 IP 地址的流量
4. **性能监控**: 记录数据包处理延迟
5. **过滤功能**: 只统计特定端口或协议的数据包

## 参考资料

- [eBPF 官方文档](https://ebpf.io/)
- [libbpf 库](https://github.com/libbpf/libbpf)
- [XDP 教程](https://github.com/xdp-project/xdp-tutorial)
- [BPF and XDP Reference Guide](https://docs.cilium.io/en/latest/bpf/)

## 许可证

GPL (与 eBPF 程序的许可证要求一致)
