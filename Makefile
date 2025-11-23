# Makefile for network-monitor eBPF project

# 编译器和工具
CLANG := clang
LLC := llc
CC := gcc

# 目录
SRC_DIR := src
OBJ_DIR := obj

# 目标文件
BPF_OBJ := $(SRC_DIR)/packet_counter.bpf.o
USER_PROG := network-monitor

# 编译选项
CLANG_FLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86
CC_FLAGS := -O2 -g -Wall
LIBS := -lbpf -lelf -lz

# BPF 头文件路径（根据系统调整）
BPF_INCLUDES := -I/usr/include

.PHONY: all clean install help

all: $(BPF_OBJ) $(USER_PROG)

# 编译 eBPF C 程序到字节码
$(BPF_OBJ): $(SRC_DIR)/packet_counter.bpf.c
	@echo "Compiling eBPF program..."
	$(CLANG) $(CLANG_FLAGS) $(BPF_INCLUDES) -c $< -o $@

# 编译用户空间程序
$(USER_PROG): $(SRC_DIR)/monitor.c $(BPF_OBJ)
	@echo "Compiling user-space program..."
	$(CC) $(CC_FLAGS) $(BPF_INCLUDES) $< -o $@ $(LIBS)

# 清理编译产物
clean:
	@echo "Cleaning up..."
	rm -f $(BPF_OBJ) $(USER_PROG)
	rm -rf $(OBJ_DIR)

# 安装（需要 root 权限）
install: all
	@echo "Installing network-monitor..."
	sudo cp $(USER_PROG) /usr/local/bin/
	@echo "Installation complete!"

# 帮助信息
help:
	@echo "Network Monitor - eBPF Packet Counter"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build the project (default)"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install to /usr/local/bin (requires root)"
	@echo "  help     - Show this help message"
	@echo ""
	@echo "Usage after build:"
	@echo "  sudo ./network-monitor <interface>"
	@echo "  Example: sudo ./network-monitor eth0"
