# Makefile for network-monitor eBPF project

# 编译器和工具
CLANG := clang
LLC := llc
CC := gcc

# 目录
SRC_DIR := src
INCLUDE_DIR := include
OBJ_DIR := obj

# 目标文件
BPF_OBJ := $(SRC_DIR)/monitor.bpf.o
MONITOR := netmon

# 编译选项
CLANG_FLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86
CC_FLAGS := -O2 -g -Wall
LIBS := -lbpf -lelf -lz

# BPF 头文件路径（根据系统调整）
BPF_INCLUDES := -I/usr/include -I$(INCLUDE_DIR)

.PHONY: all clean install help

all: $(BPF_OBJ) $(MONITOR)

# 编译 eBPF C 程序到字节码
$(BPF_OBJ): $(SRC_DIR)/monitor.bpf.c
	@echo "Compiling eBPF program..."
	$(CLANG) $(CLANG_FLAGS) $(BPF_INCLUDES) -c $< -o $@

# 编译用户空间程序
$(MONITOR): $(SRC_DIR)/main.c $(BPF_OBJ)
	@echo "Compiling network monitor..."
	$(CC) $(CC_FLAGS) $(BPF_INCLUDES) $< -o $@ $(LIBS)

# 清理编译产物
clean:
	@echo "Cleaning up..."
	rm -f $(BPF_OBJ) $(MONITOR)
	rm -rf $(OBJ_DIR)

# 安装（需要 root 权限）
install: all
	@echo "Installing network monitor..."
	sudo cp $(MONITOR) /usr/local/bin/
	@echo "Installation complete!"

# 帮助信息
help:
	@echo "Network Monitor - eBPF-based Integrated Network & ARP Monitor"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build the network monitor (default)"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install to /usr/local/bin (requires root)"
	@echo "  help     - Show this help message"
	@echo ""
	@echo "Usage after build:"
	@echo "  sudo ./netmon <interface>"
	@echo "  Example: sudo ./netmon eth0"
	@echo ""
	@echo "Features:"
	@echo "  • Real-time packet counting for all network traffic"
	@echo "  • ARP packet monitoring (Request/Reply) via XDP"
	@echo "  • ARP table change tracking (Add/Delete/Update) via Netlink"
	@echo "  • Comprehensive statistics display every 10 seconds"
	@echo ""
