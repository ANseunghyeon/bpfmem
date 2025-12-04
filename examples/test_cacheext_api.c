/*
 * test_cacheext_api.c - cacheext threaded API 동작 테스트
 *
 * 목적: cache_ext() API가 제대로 동작하는지 확인
 *       - 시작: fifo 정책 적용
 *       - 10초마다: mru, mglru 정책으로 순차 변경
 *       (in-process 스레드 방식으로 BPF 직접 로드/attach)
 *
 * 빌드: make -C ../policies (libcacheext.a 생성 필요)
 *       gcc -o test_cacheext_api test_cacheext_api.c \
 *           -I../policies -L../policies -lcacheext \
 *           -L/usr/local/lib64 -Wl,-rpath,/usr/local/lib64 -lbpf \
 *           -lelf -lz -lpthread
 *
 * 실행: sudo ./test_cacheext_api --cgroup_path /sys/fs/cgroup/test_cg --watch_dir /tmp
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>

#include "cacheext_api.h"

static volatile int running = 1;

static void sig_handler(int sig) {
    (void)sig;
    running = 0;
}

// ftrace marker에 기록
static void trace_marker(const char *msg) {
    int fd = open("/sys/kernel/debug/tracing/trace_marker", O_WRONLY);
    if (fd >= 0) {
        ssize_t ret = write(fd, msg, strlen(msg));
        (void)ret;  // 반환값 무시
        close(fd);
    }
    printf("[TRACE] %s\n", msg);
}

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s --cgroup_path <path> --watch_dir <dir> [--cgroup_size <bytes>]\n"
        "\n"
        "  --cgroup_path, -c   cgroup 경로 (예: /sys/fs/cgroup/test_cg)\n"
        "  --watch_dir, -w     감시할 디렉토리 (예: /tmp)\n"
        "  --cgroup_size, -s   cgroup 크기 (S3FIFO용, 기본: 256MB)\n"
        "\n"
        "예시:\n"
        "  sudo cgcreate -g memory:test_cg\n"
        "  sudo %s --cgroup_path /sys/fs/cgroup/test_cg --watch_dir /tmp\n",
        prog, prog);
}

int main(int argc, char **argv) {
    char *cgroup_path = NULL;
    char *watch_dir = NULL;
    unsigned long cgroup_size = 256 * 1024 * 1024;  // 256MB default

    static struct option long_opts[] = {
        {"cgroup_path", required_argument, 0, 'c'},
        {"watch_dir", required_argument, 0, 'w'},
        {"cgroup_size", required_argument, 0, 's'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "c:w:s:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'c':
            cgroup_path = optarg;
            break;
        case 'w':
            watch_dir = optarg;
            break;
        case 's':
            cgroup_size = strtoul(optarg, NULL, 10);
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    if (!cgroup_path || !watch_dir) {
        fprintf(stderr, "Error: --cgroup_path and --watch_dir are required\n");
        print_usage(argv[0]);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("===========================================\n");
    printf("cacheext_api 동작 테스트\n");
    printf("===========================================\n");
    printf("cgroup_path: %s\n", cgroup_path);
    printf("watch_dir:   %s\n", watch_dir);
    printf("cgroup_size: %lu bytes\n", cgroup_size);
    printf("\n");

    // 테스트할 정책 순서
    const char *policies[] = {"fifo", "mru", "mglru"};
    int num_policies = sizeof(policies) / sizeof(policies[0]);
    int policy_idx = 0;

    double start = now_sec();
    double step_sec = 10.0;  // 10초마다 정책 변경
    double next_switch = start;

    // 첫 번째 정책 적용
    printf("[%.1f] 정책 적용: %s\n", 0.0, policies[policy_idx]);
    
    char marker[128];
    snprintf(marker, sizeof(marker), "CACHEEXT_SWITCH_TO_%s", policies[policy_idx]);
    trace_marker(marker);
    
    int rc = cache_ext(policies[policy_idx], cgroup_path, watch_dir, cgroup_size);
    if (rc != 0) {
        fprintf(stderr, "ERROR: cache_ext(%s) failed: %d\n", policies[policy_idx], rc);
        return 1;
    }
    printf("[%.1f] 정책 적용 성공: %s\n", now_sec() - start, policies[policy_idx]);
    
    policy_idx++;
    next_switch = start + policy_idx * step_sec;

    // 메인 루프: 10초마다 정책 변경
    while (running) {
        double now = now_sec();
        double elapsed = now - start;

        // 정책 변경 시점 체크
        if (now >= next_switch && policy_idx < num_policies) {
            printf("\n[%.1f] 정책 변경 시작: %s -> %s\n", 
                   elapsed, policies[policy_idx - 1], policies[policy_idx]);

            snprintf(marker, sizeof(marker), "CACHEEXT_SWITCH_TO_%s", policies[policy_idx]);
            trace_marker(marker);

            rc = cache_ext(policies[policy_idx], cgroup_path, watch_dir, cgroup_size);
            if (rc != 0) {
                fprintf(stderr, "ERROR: cache_ext(%s) failed: %d\n", policies[policy_idx], rc);
            } else {
                printf("[%.1f] 정책 변경 성공: %s\n", now_sec() - start, policies[policy_idx]);
            }

            policy_idx++;
            next_switch = start + policy_idx * step_sec;
        }

        // 모든 정책 테스트 완료
        if (policy_idx >= num_policies && now >= next_switch) {
            printf("\n[%.1f] 모든 정책 테스트 완료!\n", elapsed);
            break;
        }

        // 상태 출력 (5초마다)
        static double last_print = 0;
        if (now - last_print >= 5.0) {
            printf("[%.1f] 현재 정책: %s, 다음 변경까지: %.1f초\n",
                   elapsed, 
                   policies[policy_idx > 0 ? policy_idx - 1 : 0],
                   next_switch - now);
            last_print = now;
        }

        usleep(100000);  // 100ms
    }

    // 정리
    printf("\n종료 중... 정책 해제\n");
    trace_marker("CACHEEXT_SHUTDOWN");
    cache_ext_shutdown();
    printf("완료!\n");

    return 0;
}

