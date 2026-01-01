/*
 * multi_phase_workload.c
 * 
 * A synthetic workload with distinct memory access phases designed to
 * demonstrate the benefits of dynamic policy switching.
 * 
 * Phases:
 *   1. MRU-favorable:  Stack-like LIFO access (most recent accessed repeatedly)
 *   2. LRU-favorable:  Working set with temporal locality 
 *   3. FIFO-favorable: Sequential scan (cold data)
 *   4. S3FIFO-favorable: Mixed - sequential with occasional re-access
 *
 * Compile: gcc -O2 -o multi_phase_workload multi_phase_workload.c -lpthread -lrt
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <pthread.h>

#define PAGE_SIZE 4096
#define DEFAULT_FILE_SIZE_MB 256
#define DEFAULT_WORKING_SET_MB 64
#define DEFAULT_PHASE_ITERATIONS 5
#define DEFAULT_OUTPUT_DIR "/tmp/14weeks_results"

static volatile int g_running = 1;

struct latency_stats {
    unsigned long long count;
    unsigned long long sum_ns;
    unsigned long long min_ns;
    unsigned long long max_ns;
    unsigned long long *histogram;  // buckets: 0-1us, 1-10us, 10-100us, 100us-1ms, 1-10ms, 10-100ms, >100ms
    size_t hist_size;
    pthread_mutex_t lock;
};

struct phase_result {
    const char *name;
    unsigned long long start_ns;
    unsigned long long end_ns;
    unsigned long long total_accesses;
    struct latency_stats lat;
};

struct workload_config {
    size_t file_size;
    size_t working_set_size;
    int phase_iterations;
    const char *data_dir;
    const char *output_dir;
    int verbose;
    int measure_latency;
    int drop_caches_between_phases;
};

static unsigned long long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static void lat_init(struct latency_stats *s) {
    memset(s, 0, sizeof(*s));
    s->min_ns = ~0ULL;
    s->hist_size = 7;
    s->histogram = calloc(s->hist_size, sizeof(unsigned long long));
    pthread_mutex_init(&s->lock, NULL);
}

static void lat_record(struct latency_stats *s, unsigned long long ns) {
    pthread_mutex_lock(&s->lock);
    s->count++;
    s->sum_ns += ns;
    if (ns < s->min_ns) s->min_ns = ns;
    if (ns > s->max_ns) s->max_ns = ns;
    
    // Histogram buckets (in ns)
    if (ns < 1000) s->histogram[0]++;           // <1us
    else if (ns < 10000) s->histogram[1]++;     // 1-10us
    else if (ns < 100000) s->histogram[2]++;    // 10-100us
    else if (ns < 1000000) s->histogram[3]++;   // 100us-1ms
    else if (ns < 10000000) s->histogram[4]++;  // 1-10ms
    else if (ns < 100000000) s->histogram[5]++; // 10-100ms
    else s->histogram[6]++;                      // >100ms
    pthread_mutex_unlock(&s->lock);
}

static void lat_destroy(struct latency_stats *s) {
    free(s->histogram);
    pthread_mutex_destroy(&s->lock);
}

static int create_data_file(const char *path, size_t size) {
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open data file");
        return -1;
    }
    
    // Use fallocate if available, else write zeros
    if (fallocate(fd, 0, 0, size) < 0) {
        // Fallback: write zeros
        char *zeros = calloc(1, PAGE_SIZE);
        if (!zeros) {
            close(fd);
            return -1;
        }
        size_t written = 0;
        while (written < size) {
            size_t chunk = (size - written > PAGE_SIZE) ? PAGE_SIZE : (size - written);
            if (write(fd, zeros, chunk) != (ssize_t)chunk) {
                free(zeros);
                close(fd);
                return -1;
            }
            written += chunk;
        }
        free(zeros);
    }
    
    close(fd);
    return 0;
}

static void drop_caches(void) {
    int fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (fd >= 0) {
        (void)write(fd, "3", 1);
        close(fd);
    }
    sync();
}

static void phase_announce(const char *phase_name, int iteration, int total) {
    fprintf(stdout, "\n[PHASE] %s (iteration %d/%d) starting...\n", 
            phase_name, iteration, total);
    fflush(stdout);
}

/*
 * Phase 1: MRU-favorable pattern
 * Stack-like LIFO access: push items then pop them (most recent first)
 * This benefits MRU because recently added items are accessed first.
 */
static void run_mru_phase(int fd, size_t file_size, struct phase_result *res, 
                          const struct workload_config *cfg) {
    size_t num_pages = file_size / PAGE_SIZE;
    size_t stack_depth = num_pages / 4;  // Use 1/4 of file as stack
    
    char *buf = aligned_alloc(PAGE_SIZE, PAGE_SIZE);
    if (!buf) return;
    
    res->start_ns = now_ns();
    res->total_accesses = 0;
    
    // Simulate stack operations: push N items, then pop all
    for (int round = 0; round < cfg->phase_iterations * 2; round++) {
        // "Push" phase: sequential writes to stack area
        for (size_t i = 0; i < stack_depth; i++) {
            off_t offset = i * PAGE_SIZE;
            unsigned long long t0 = cfg->measure_latency ? now_ns() : 0;
            
            pread(fd, buf, PAGE_SIZE, offset);
            buf[0] = (char)(round ^ i);  // Touch the page
            pwrite(fd, buf, PAGE_SIZE, offset);
            
            if (cfg->measure_latency) {
                lat_record(&res->lat, now_ns() - t0);
            }
            res->total_accesses++;
        }
        
        // "Pop" phase: reverse order access (LIFO - most recent first)
        for (size_t i = stack_depth; i > 0; i--) {
            off_t offset = (i - 1) * PAGE_SIZE;
            unsigned long long t0 = cfg->measure_latency ? now_ns() : 0;
            
            pread(fd, buf, PAGE_SIZE, offset);
            
            if (cfg->measure_latency) {
                lat_record(&res->lat, now_ns() - t0);
            }
            res->total_accesses++;
        }
    }
    
    res->end_ns = now_ns();
    free(buf);
}

/*
 * Phase 2: LRU-favorable pattern  
 * Working set access with temporal locality: repeatedly access same working set
 * This benefits LRU because frequently used pages stay in cache.
 */
static void run_lru_phase(int fd, size_t file_size, struct phase_result *res,
                          const struct workload_config *cfg) {
    size_t ws_pages = cfg->working_set_size / PAGE_SIZE;
    size_t total_pages = file_size / PAGE_SIZE;
    
    char *buf = aligned_alloc(PAGE_SIZE, PAGE_SIZE);
    if (!buf) return;
    
    // Create random access pattern within working set
    size_t *access_order = malloc(ws_pages * sizeof(size_t));
    if (!access_order) {
        free(buf);
        return;
    }
    
    // Initialize with sequential then shuffle
    for (size_t i = 0; i < ws_pages; i++) {
        access_order[i] = i;
    }
    // Fisher-Yates shuffle
    srand(42);
    for (size_t i = ws_pages - 1; i > 0; i--) {
        size_t j = rand() % (i + 1);
        size_t tmp = access_order[i];
        access_order[i] = access_order[j];
        access_order[j] = tmp;
    }
    
    res->start_ns = now_ns();
    res->total_accesses = 0;
    
    // Repeated working set access with temporal locality
    int loops = cfg->phase_iterations * 10;
    for (int round = 0; round < loops; round++) {
        for (size_t i = 0; i < ws_pages; i++) {
            // Access within working set region (starts at 1/4 of file)
            size_t page_idx = (total_pages / 4) + access_order[i];
            if (page_idx >= total_pages) page_idx = access_order[i];
            
            off_t offset = page_idx * PAGE_SIZE;
            unsigned long long t0 = cfg->measure_latency ? now_ns() : 0;
            
            pread(fd, buf, PAGE_SIZE, offset);
            
            if (cfg->measure_latency) {
                lat_record(&res->lat, now_ns() - t0);
            }
            res->total_accesses++;
        }
    }
    
    res->end_ns = now_ns();
    free(access_order);
    free(buf);
}

/*
 * Phase 3: FIFO-favorable pattern
 * Pure sequential scan: each page accessed once in order
 * This benefits FIFO because there's no recency benefit.
 */
static void run_fifo_phase(int fd, size_t file_size, struct phase_result *res,
                           const struct workload_config *cfg) {
    size_t num_pages = file_size / PAGE_SIZE;
    
    char *buf = aligned_alloc(PAGE_SIZE, PAGE_SIZE);
    if (!buf) return;
    
    res->start_ns = now_ns();
    res->total_accesses = 0;
    
    for (int round = 0; round < cfg->phase_iterations; round++) {
        // Sequential scan through entire file
        for (size_t i = 0; i < num_pages; i++) {
            off_t offset = i * PAGE_SIZE;
            unsigned long long t0 = cfg->measure_latency ? now_ns() : 0;
            
            pread(fd, buf, PAGE_SIZE, offset);
            
            if (cfg->measure_latency) {
                lat_record(&res->lat, now_ns() - t0);
            }
            res->total_accesses++;
            
            if (!g_running) break;
        }
        if (!g_running) break;
    }
    
    res->end_ns = now_ns();
    free(buf);
}

/*
 * Phase 4: S3FIFO-favorable pattern
 * Sequential with occasional re-access (ghost hits)
 * This benefits S3FIFO's admission policy for detecting one-hit wonders.
 */
static void run_s3fifo_phase(int fd, size_t file_size, struct phase_result *res,
                              const struct workload_config *cfg) {
    size_t num_pages = file_size / PAGE_SIZE;
    size_t reaccess_window = num_pages / 8;  // Re-access items within this window
    
    char *buf = aligned_alloc(PAGE_SIZE, PAGE_SIZE);
    if (!buf) return;
    
    res->start_ns = now_ns();
    res->total_accesses = 0;
    
    srand(123);
    
    for (int round = 0; round < cfg->phase_iterations; round++) {
        for (size_t i = 0; i < num_pages; i++) {
            off_t offset = i * PAGE_SIZE;
            unsigned long long t0 = cfg->measure_latency ? now_ns() : 0;
            
            pread(fd, buf, PAGE_SIZE, offset);
            
            if (cfg->measure_latency) {
                lat_record(&res->lat, now_ns() - t0);
            }
            res->total_accesses++;
            
            // 30% chance to re-access a recent page (within window)
            if ((rand() % 100) < 30 && i > 0) {
                size_t back = (rand() % reaccess_window);
                if (back > i) back = i;
                size_t reaccess_idx = i - back;
                
                off_t reoffset = reaccess_idx * PAGE_SIZE;
                t0 = cfg->measure_latency ? now_ns() : 0;
                
                pread(fd, buf, PAGE_SIZE, reoffset);
                
                if (cfg->measure_latency) {
                    lat_record(&res->lat, now_ns() - t0);
                }
                res->total_accesses++;
            }
            
            if (!g_running) break;
        }
        if (!g_running) break;
    }
    
    res->end_ns = now_ns();
    free(buf);
}

/*
 * Phase 5: Mixed/Random access (baseline comparison)
 * Uniform random access pattern
 */
static void run_random_phase(int fd, size_t file_size, struct phase_result *res,
                              const struct workload_config *cfg) {
    size_t num_pages = file_size / PAGE_SIZE;
    size_t accesses_per_round = num_pages;
    
    char *buf = aligned_alloc(PAGE_SIZE, PAGE_SIZE);
    if (!buf) return;
    
    res->start_ns = now_ns();
    res->total_accesses = 0;
    
    srand(456);
    
    for (int round = 0; round < cfg->phase_iterations; round++) {
        for (size_t i = 0; i < accesses_per_round; i++) {
            size_t page_idx = rand() % num_pages;
            off_t offset = page_idx * PAGE_SIZE;
            unsigned long long t0 = cfg->measure_latency ? now_ns() : 0;
            
            pread(fd, buf, PAGE_SIZE, offset);
            
            if (cfg->measure_latency) {
                lat_record(&res->lat, now_ns() - t0);
            }
            res->total_accesses++;
            
            if (!g_running) break;
        }
        if (!g_running) break;
    }
    
    res->end_ns = now_ns();
    free(buf);
}

static void write_phase_results(FILE *fp, struct phase_result *res) {
    double duration_sec = (res->end_ns - res->start_ns) / 1e9;
    double avg_lat_us = res->lat.count > 0 ? 
        (res->lat.sum_ns / (double)res->lat.count) / 1000.0 : 0;
    
    fprintf(fp, "%s,%.6f,%llu,%.3f,%.3f,%.3f,",
            res->name,
            duration_sec,
            res->total_accesses,
            res->lat.min_ns / 1000.0,
            avg_lat_us,
            res->lat.max_ns / 1000.0);
    
    // Histogram percentages
    double total = (double)res->lat.count;
    if (total > 0) {
        for (size_t i = 0; i < res->lat.hist_size; i++) {
            fprintf(fp, "%.4f", (res->lat.histogram[i] / total) * 100.0);
            if (i < res->lat.hist_size - 1) fprintf(fp, ",");
        }
    } else {
        for (size_t i = 0; i < res->lat.hist_size; i++) {
            fprintf(fp, "0");
            if (i < res->lat.hist_size - 1) fprintf(fp, ",");
        }
    }
    fprintf(fp, "\n");
}

static void print_summary(struct phase_result *results, int num_phases) {
    printf("\n==================== WORKLOAD SUMMARY ====================\n");
    printf("%-12s %12s %15s %12s %12s\n", 
           "Phase", "Duration(s)", "Accesses", "Avg Lat(us)", "Throughput");
    printf("------------------------------------------------------------\n");
    
    unsigned long long total_time = 0;
    unsigned long long total_accesses = 0;
    
    for (int i = 0; i < num_phases; i++) {
        struct phase_result *r = &results[i];
        double dur = (r->end_ns - r->start_ns) / 1e9;
        double avg_lat = r->lat.count > 0 ? 
            (r->lat.sum_ns / (double)r->lat.count) / 1000.0 : 0;
        double throughput = r->total_accesses / dur;
        
        printf("%-12s %12.3f %15llu %12.2f %12.0f\n",
               r->name, dur, r->total_accesses, avg_lat, throughput);
        
        total_time += (r->end_ns - r->start_ns);
        total_accesses += r->total_accesses;
    }
    
    printf("------------------------------------------------------------\n");
    printf("%-12s %12.3f %15llu\n", "TOTAL", total_time / 1e9, total_accesses);
    printf("============================================================\n\n");
}

static void usage(const char *prog) {
    fprintf(stderr, 
        "Usage: %s [options]\n"
        "\n"
        "Multi-phase workload for cache policy evaluation.\n"
        "\n"
        "Options:\n"
        "  -s, --size MB        Data file size in MB (default: %d)\n"
        "  -w, --working-set MB Working set size in MB (default: %d)\n"
        "  -i, --iterations N   Iterations per phase (default: %d)\n"
        "  -d, --data-dir DIR   Directory for data files (default: /tmp)\n"
        "  -o, --output-dir DIR Results output directory\n"
        "  -l, --latency        Measure per-access latency (slower)\n"
        "  -D, --drop-caches    Drop caches between phases\n"
        "  -v, --verbose        Verbose output\n"
        "  -h, --help           Show this help\n"
        "\n"
        "Phases executed in order:\n"
        "  1. MRU:    Stack-like LIFO access pattern\n"
        "  2. LRU:    Working set with temporal locality\n"
        "  3. FIFO:   Pure sequential scan\n"
        "  4. S3FIFO: Sequential with re-access\n"
        "  5. RANDOM: Uniform random access\n"
        "\n",
        prog, DEFAULT_FILE_SIZE_MB, DEFAULT_WORKING_SET_MB, DEFAULT_PHASE_ITERATIONS);
}

int main(int argc, char **argv) {
    struct workload_config cfg = {
        .file_size = DEFAULT_FILE_SIZE_MB * 1024UL * 1024UL,
        .working_set_size = DEFAULT_WORKING_SET_MB * 1024UL * 1024UL,
        .phase_iterations = DEFAULT_PHASE_ITERATIONS,
        .data_dir = "/tmp",
        .output_dir = DEFAULT_OUTPUT_DIR,
        .verbose = 0,
        .measure_latency = 0,
        .drop_caches_between_phases = 0,
    };
    
    static struct option long_opts[] = {
        {"size", required_argument, 0, 's'},
        {"working-set", required_argument, 0, 'w'},
        {"iterations", required_argument, 0, 'i'},
        {"data-dir", required_argument, 0, 'd'},
        {"output-dir", required_argument, 0, 'o'},
        {"latency", no_argument, 0, 'l'},
        {"drop-caches", no_argument, 0, 'D'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "s:w:i:d:o:lDvh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 's':
            cfg.file_size = atol(optarg) * 1024UL * 1024UL;
            break;
        case 'w':
            cfg.working_set_size = atol(optarg) * 1024UL * 1024UL;
            break;
        case 'i':
            cfg.phase_iterations = atoi(optarg);
            break;
        case 'd':
            cfg.data_dir = optarg;
            break;
        case 'o':
            cfg.output_dir = optarg;
            break;
        case 'l':
            cfg.measure_latency = 1;
            break;
        case 'D':
            cfg.drop_caches_between_phases = 1;
            break;
        case 'v':
            cfg.verbose = 1;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // Create output directory
    char mkdir_cmd[512];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", cfg.output_dir);
    system(mkdir_cmd);
    
    // Create data file
    char data_path[512];
    snprintf(data_path, sizeof(data_path), "%s/workload_data.bin", cfg.data_dir);
    
    printf("[INFO] Creating data file: %s (%zu MB)\n", data_path, cfg.file_size / (1024*1024));
    if (create_data_file(data_path, cfg.file_size) < 0) {
        fprintf(stderr, "Failed to create data file\n");
        return 1;
    }
    

    int fd = open(data_path, O_RDWR);
    if (fd < 0) {
        perror("open data file");
        return 1;
    }
    
    // Prepare results
    #define NUM_PHASES 5
    struct phase_result results[NUM_PHASES];
    memset(results, 0, sizeof(results));
    
    results[0].name = "MRU";
    results[1].name = "LRU";
    results[2].name = "FIFO";
    results[3].name = "S3FIFO";
    results[4].name = "RANDOM";
    
    for (int i = 0; i < NUM_PHASES; i++) {
        lat_init(&results[i].lat);
    }
    
    printf("\n[INFO] Starting multi-phase workload\n");
    printf("[INFO] File size: %zu MB, Working set: %zu MB, Iterations: %d\n",
           cfg.file_size / (1024*1024), 
           cfg.working_set_size / (1024*1024),
           cfg.phase_iterations);
    printf("[INFO] Latency measurement: %s\n", cfg.measure_latency ? "ON" : "OFF");
    
    unsigned long long workload_start = now_ns();
    
    // Phase 1: MRU
    if (g_running) {
        phase_announce("MRU-favorable (LIFO stack access)", 1, NUM_PHASES);
        if (cfg.drop_caches_between_phases) drop_caches();
        run_mru_phase(fd, cfg.file_size, &results[0], &cfg);
    }
    
    // Phase 2: LRU
    if (g_running) {
        phase_announce("LRU-favorable (working set)", 2, NUM_PHASES);
        if (cfg.drop_caches_between_phases) drop_caches();
        run_lru_phase(fd, cfg.file_size, &results[1], &cfg);
    }
    
    // Phase 3: FIFO
    if (g_running) {
        phase_announce("FIFO-favorable (sequential scan)", 3, NUM_PHASES);
        if (cfg.drop_caches_between_phases) drop_caches();
        run_fifo_phase(fd, cfg.file_size, &results[2], &cfg);
    }
    
    // Phase 4: S3FIFO
    if (g_running) {
        phase_announce("S3FIFO-favorable (seq + re-access)", 4, NUM_PHASES);
        if (cfg.drop_caches_between_phases) drop_caches();
        run_s3fifo_phase(fd, cfg.file_size, &results[3], &cfg);
    }
    
    // Phase 5: Random
    if (g_running) {
        phase_announce("RANDOM (uniform random)", 5, NUM_PHASES);
        if (cfg.drop_caches_between_phases) drop_caches();
        run_random_phase(fd, cfg.file_size, &results[4], &cfg);
    }
    
    unsigned long long workload_end = now_ns();
    
    close(fd);
    
    // Print summary
    print_summary(results, NUM_PHASES);
    
    // Write detailed results
    char csv_path[512];
    snprintf(csv_path, sizeof(csv_path), "%s/phase_results.csv", cfg.output_dir);
    FILE *csv = fopen(csv_path, "w");
    if (csv) {
        fprintf(csv, "phase,duration_sec,accesses,lat_min_us,lat_avg_us,lat_max_us,"
                     "pct_lt1us,pct_1_10us,pct_10_100us,pct_100us_1ms,"
                     "pct_1_10ms,pct_10_100ms,pct_gt100ms\n");
        for (int i = 0; i < NUM_PHASES; i++) {
            write_phase_results(csv, &results[i]);
        }
        fclose(csv);
        printf("[INFO] Results written to: %s\n", csv_path);
    }
    
    // Write summary JSON
    char json_path[512];
    snprintf(json_path, sizeof(json_path), "%s/summary.json", cfg.output_dir);
    FILE *json = fopen(json_path, "w");
    if (json) {
        fprintf(json, "{\n");
        fprintf(json, "  \"total_duration_sec\": %.6f,\n", 
                (workload_end - workload_start) / 1e9);
        fprintf(json, "  \"file_size_mb\": %zu,\n", cfg.file_size / (1024*1024));
        fprintf(json, "  \"working_set_mb\": %zu,\n", cfg.working_set_size / (1024*1024));
        fprintf(json, "  \"iterations_per_phase\": %d,\n", cfg.phase_iterations);
        fprintf(json, "  \"phases\": [\n");
        for (int i = 0; i < NUM_PHASES; i++) {
            struct phase_result *r = &results[i];
            fprintf(json, "    {\n");
            fprintf(json, "      \"name\": \"%s\",\n", r->name);
            fprintf(json, "      \"duration_sec\": %.6f,\n", (r->end_ns - r->start_ns) / 1e9);
            fprintf(json, "      \"accesses\": %llu,\n", r->total_accesses);
            fprintf(json, "      \"throughput\": %.2f\n", 
                    r->total_accesses / ((r->end_ns - r->start_ns) / 1e9));
            fprintf(json, "    }%s\n", i < NUM_PHASES - 1 ? "," : "");
        }
        fprintf(json, "  ]\n");
        fprintf(json, "}\n");
        fclose(json);
        printf("[INFO] Summary written to: %s\n", json_path);
    }
    
    // Cleanup
    for (int i = 0; i < NUM_PHASES; i++) {
        lat_destroy(&results[i].lat);
    }
    
    // Remove data file
    if (cfg.verbose) {
        printf("[INFO] Keeping data file: %s\n", data_path);
    } else {
        unlink(data_path);
    }
    
    printf("[DONE] Multi-phase workload completed.\n");
    return 0;
}

