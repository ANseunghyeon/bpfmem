/*
 * test_workload.c - Sequential/Random 읽기 워크로드 생성기
 * 
 * 사용법:
 *   ./test_workload --mode seq|rand --file <path> --iterations <n>
 * 
 * seq: 순차 읽기 (FIFO에 유리)
 * rand: 랜덤 읽기 (MGLRU에 유리)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <getopt.h>

#define PAGE_SIZE 4096
#define DEFAULT_ITERATIONS 100

static void sequential_read(int fd, off_t file_size) {
    char buf[PAGE_SIZE];
    lseek(fd, 0, SEEK_SET);
    
    off_t pos = 0;
    while (pos < file_size) {
        ssize_t n = read(fd, buf, PAGE_SIZE);
        if (n <= 0) break;
        pos += n;
    }
}

static void random_read(int fd, off_t file_size) {
    char buf[PAGE_SIZE];
    int num_pages = file_size / PAGE_SIZE;
    if (num_pages < 1) num_pages = 1;
    
    // 랜덤하게 페이지 접근 (페이지 수만큼 접근)
    for (int i = 0; i < num_pages; i++) {
        off_t page_idx = rand() % num_pages;
        off_t offset = page_idx * PAGE_SIZE;
        lseek(fd, offset, SEEK_SET);
        read(fd, buf, PAGE_SIZE);
    }
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s --mode seq|rand --file <path> [--iterations <n>]\n"
        "  --mode, -m      seq (sequential) or rand (random)\n"
        "  --file, -f      Target file to read\n"
        "  --iterations, -i Number of iterations (default: %d)\n"
        "\n"
        "Example:\n"
        "  %s --mode seq --file /path/to/largefile --iterations 50\n",
        prog, DEFAULT_ITERATIONS, prog);
}

int main(int argc, char **argv) {
    char *mode = NULL;
    char *filepath = NULL;
    int iterations = DEFAULT_ITERATIONS;

    static struct option long_opts[] = {
        {"mode", required_argument, 0, 'm'},
        {"file", required_argument, 0, 'f'},
        {"iterations", required_argument, 0, 'i'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "m:f:i:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'm':
            mode = optarg;
            break;
        case 'f':
            filepath = optarg;
            break;
        case 'i':
            iterations = atoi(optarg);
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    if (!mode || !filepath) {
        fprintf(stderr, "Error: --mode and --file are required\n");
        print_usage(argv[0]);
        return 1;
    }

    int is_sequential = (strcmp(mode, "seq") == 0);
    if (!is_sequential && strcmp(mode, "rand") != 0) {
        fprintf(stderr, "Error: mode must be 'seq' or 'rand'\n");
        return 1;
    }

    srand(time(NULL) ^ getpid());

    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return 1;
    }
    off_t file_size = st.st_size;

    printf("[test_workload] mode=%s file=%s size=%ld iterations=%d\n",
           mode, filepath, file_size, iterations);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < iterations; i++) {
        if (is_sequential) {
            sequential_read(fd, file_size);
        } else {
            random_read(fd, file_size);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + 
                     (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("[test_workload] completed in %.3f seconds\n", elapsed);

    close(fd);
    return 0;
}




