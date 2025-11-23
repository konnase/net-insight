#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>

static volatile sig_atomic_t keep_running = 1;

void sig_handler(int signo)
{
    keep_running = 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd, map_fd;
    int ifindex;
    __u32 key = 0;
    __u64 count;
    int err;

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
    obj = bpf_object__open_file("src/packet_counter.bpf.o", NULL);
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
    prog = bpf_object__find_program_by_name(obj, "xdp_packet_counter");
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

    printf("Successfully attached XDP program to %s\n", argv[1]);
    printf("Monitoring packets... Press Ctrl+C to stop\n\n");

    /* 获取 map 文件描述符 */
    map_fd = bpf_object__find_map_fd_by_name(obj, "packet_count");
    if (map_fd < 0) {
        fprintf(stderr, "Error: Failed to find map\n");
        bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
        bpf_object__close(obj);
        return 1;
    }

    /* 设置信号处理器 */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* 定期读取并显示计数器 */
    while (keep_running) {
        sleep(1);

        /* 从 map 中读取计数器值 */
        err = bpf_map_lookup_elem(map_fd, &key, &count);
        if (err == 0) {
            printf("\rPackets received: %llu", count);
            fflush(stdout);
        } else {
            fprintf(stderr, "\nError: Failed to read map: %s\n", strerror(errno));
            break;
        }
    }

    printf("\n\nDetaching XDP program...\n");

    /* 分离 XDP 程序 */
    bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);

    /* 清理 */
    bpf_object__close(obj);

    printf("Program terminated successfully\n");
    return 0;
}
