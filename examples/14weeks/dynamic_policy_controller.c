/*
 * dynamic_policy_controller.c
 * 
 * Monitors memory access patterns using mem_monitor BPF and dynamically
 * switches cache replacement policies using cacheext_threaded API.
 * 
 * Detection heuristics:
 * - MRU pattern: High recency bias, LIFO-like access
 * - LRU pattern: Working set with temporal locality
 * - FIFO pattern: Sequential scan with low re-access
 * - S3FIFO pattern: Sequential with moderate re-access
 * 
 * Compile with policies/Makefile or standalone:
 *   gcc -O2 -I../../policies -I../../IRP -I../../linux/tools/lib/bpf \
 *       -o dynamic_policy_controller dynamic_policy_controller.c \
 *       ../../policies/libcacheext.a ../../linux/tools/lib/bpf/libbpf.a \
 *       -lelf -lz -lpthread
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "mem_monitor_common.h"
#include "mem_monitor.skel.h"
#include "cacheext_api.h"

// ============================================================================
// Policy Name Helper (cacheext_api doesn't provide this)
// ============================================================================

static const char *policy_to_string(cacheext_policy_t policy) {
    switch (policy) {
    case CACHEEXT_POLICY_NONE:     return "none";
    case CACHEEXT_POLICY_FIFO:     return "fifo";
    case CACHEEXT_POLICY_MRU:      return "mru";
    case CACHEEXT_POLICY_MGLRU:    return "mglru";
    case CACHEEXT_POLICY_LHD:      return "lhd";
    case CACHEEXT_POLICY_S3FIFO:   return "s3fifo";
    case CACHEEXT_POLICY_SAMPLING: return "sampling";
    case CACHEEXT_POLICY_GET_SCAN: return "get_scan";
    default:                       return "unknown";
    }
}

// ============================================================================
// Configuration Constants
// ============================================================================

#define MAX_HISTORY_SIZE 10000
#define WINDOW_SIZE_MS 500        // Analysis window
#define MIN_SWITCH_INTERVAL_MS 2000
#define MIN_EVENTS_FOR_DECISION 100

// Pattern detection thresholds
#define SEQ_THRESHOLD 0.70        // >70% sequential = scan pattern
#define REACCESS_LOW 0.15         // <15% re-access = FIFO
#define REACCESS_MED 0.35         // 15-35% re-access = S3FIFO
#define RECENCY_HIGH 0.50         // >50% recent re-access = MRU
#define LOCALITY_HIGH 0.60        // >60% working set hits = LRU

// ============================================================================
// Access Pattern Tracking
// ============================================================================

struct access_record {
    uint64_t timestamp_ns;
    uint64_t address;      // Page-aligned address or inode+pgoff hash
    uint32_t dev;
    uint64_t ino;
    uint64_t pgoff;
    uint8_t is_sequential;
    uint8_t is_write;
};

struct pattern_stats {
    uint64_t total_accesses;
    uint64_t sequential_accesses;
    uint64_t random_accesses;
    uint64_t reaccesses;
    uint64_t recent_reaccesses;  // Re-access within last N accesses
    uint64_t working_set_hits;
    uint64_t working_set_size;
    
    // For working set tracking
    uint64_t unique_pages_seen;
    uint64_t repeated_pages;
    
    // Timing
    uint64_t window_start_ns;
    uint64_t last_event_ns;
};

struct access_tracker {
    struct access_record *history;
    size_t history_size;
    size_t history_capacity;
    size_t history_head;
    
    // Hash table for seen pages (simple open addressing)
    uint64_t *seen_pages;
    uint64_t *page_last_access;  // Index of last access
    size_t seen_capacity;
    
    struct pattern_stats stats;
    pthread_mutex_t lock;
};

// ============================================================================
// Global State
// ============================================================================

static volatile bool g_running = true;
static volatile bool g_paused = false;

static struct {
    const char *cgroup_path;
    const char *watch_dir;
    const char *output_dir;
    unsigned long cgroup_size_bytes;
    int min_switch_ms;
    int window_ms;
    int verbose;
    int log_switches;
    int dry_run;  // Don't actually switch policies
} g_config;

static struct {
    cacheext_policy_t current;
    uint64_t last_switch_ns;
    int switches_count;
    FILE *log_file;
} g_policy_state;

static struct access_tracker g_tracker;
static struct mem_monitor_bpf *g_skel;
static struct ring_buffer *g_rb;

// ============================================================================
// Utility Functions
// ============================================================================

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void sig_handler(int sig) {
    (void)sig;
    g_running = false;
}

static uint64_t hash_page(uint32_t dev, uint64_t ino, uint64_t pgoff) {
    // Simple mixing hash
    uint64_t h = dev;
    h = h * 31 + ino;
    h = h * 31 + pgoff;
    return h;
}

// ============================================================================
// Access Tracker Implementation
// ============================================================================

static int tracker_init(struct access_tracker *t, size_t capacity) {
    memset(t, 0, sizeof(*t));
    pthread_mutex_init(&t->lock, NULL);
    
    t->history_capacity = capacity;
    t->history = calloc(capacity, sizeof(struct access_record));
    if (!t->history) return -1;
    
    // Seen pages hash table (4x capacity for low load factor)
    t->seen_capacity = capacity * 4;
    t->seen_pages = calloc(t->seen_capacity, sizeof(uint64_t));
    t->page_last_access = calloc(t->seen_capacity, sizeof(uint64_t));
    if (!t->seen_pages || !t->page_last_access) {
        free(t->history);
        free(t->seen_pages);
        free(t->page_last_access);
        return -1;
    }
    
    t->stats.window_start_ns = now_ns();
    return 0;
}

static void tracker_destroy(struct access_tracker *t) {
    free(t->history);
    free(t->seen_pages);
    free(t->page_last_access);
    pthread_mutex_destroy(&t->lock);
}

static void tracker_reset_stats(struct access_tracker *t) {
    memset(&t->stats, 0, sizeof(t->stats));
    t->stats.window_start_ns = now_ns();
    
    // Clear seen pages hash
    memset(t->seen_pages, 0, t->seen_capacity * sizeof(uint64_t));
    memset(t->page_last_access, 0, t->seen_capacity * sizeof(uint64_t));
}

static size_t hash_probe(uint64_t *table, size_t cap, uint64_t key) {
    size_t idx = key % cap;
    size_t start = idx;
    while (table[idx] != 0 && table[idx] != key) {
        idx = (idx + 1) % cap;
        if (idx == start) break;  // Table full
    }
    return idx;
}

static void tracker_record_access(struct access_tracker *t,
                                   uint32_t dev, uint64_t ino, uint64_t pgoff,
                                   uint8_t is_seq, uint8_t is_write) {
    pthread_mutex_lock(&t->lock);
    
    uint64_t page_hash = hash_page(dev, ino, pgoff);
    uint64_t ts = now_ns();
    
    // Record in history
    size_t idx = t->history_head;
    t->history[idx].timestamp_ns = ts;
    t->history[idx].dev = dev;
    t->history[idx].ino = ino;
    t->history[idx].pgoff = pgoff;
    t->history[idx].is_sequential = is_seq;
    t->history[idx].is_write = is_write;
    t->history_head = (t->history_head + 1) % t->history_capacity;
    if (t->history_size < t->history_capacity) {
        t->history_size++;
    }
    
    // Update stats
    t->stats.total_accesses++;
    if (is_seq) {
        t->stats.sequential_accesses++;
    } else {
        t->stats.random_accesses++;
    }
    
    // Check if this is a re-access
    size_t hash_idx = hash_probe(t->seen_pages, t->seen_capacity, page_hash);
    if (t->seen_pages[hash_idx] == page_hash) {
        // Re-access
        t->stats.reaccesses++;
        t->stats.repeated_pages++;
        
        // Check if recent re-access (within last 1000 accesses)
        uint64_t last_idx = t->page_last_access[hash_idx];
        if (t->stats.total_accesses - last_idx < 1000) {
            t->stats.recent_reaccesses++;
        }
        
        // Check working set hit
        if (t->stats.total_accesses - last_idx < t->stats.working_set_size + 500) {
            t->stats.working_set_hits++;
        }
        
        t->page_last_access[hash_idx] = t->stats.total_accesses;
    } else {
        // New page
        t->seen_pages[hash_idx] = page_hash;
        t->page_last_access[hash_idx] = t->stats.total_accesses;
        t->stats.unique_pages_seen++;
    }
    
    // Estimate working set size (pages seen in recent window)
    if (t->stats.unique_pages_seen > 0) {
        t->stats.working_set_size = t->stats.unique_pages_seen / 4;  // Heuristic
    }
    
    t->stats.last_event_ns = ts;
    
    pthread_mutex_unlock(&t->lock);
}

// ============================================================================
// Pattern Detection
// ============================================================================

typedef enum {
    PATTERN_UNKNOWN = 0,
    PATTERN_MRU,
    PATTERN_LRU,
    PATTERN_FIFO,
    PATTERN_S3FIFO,
} pattern_type_t;

static const char *pattern_name(pattern_type_t p) {
    switch (p) {
    case PATTERN_MRU: return "MRU";
    case PATTERN_LRU: return "LRU";
    case PATTERN_FIFO: return "FIFO";
    case PATTERN_S3FIFO: return "S3FIFO";
    default: return "UNKNOWN";
    }
}

static pattern_type_t detect_pattern(struct access_tracker *t) {
    pthread_mutex_lock(&t->lock);
    
    struct pattern_stats *s = &t->stats;
    
    if (s->total_accesses < MIN_EVENTS_FOR_DECISION) {
        pthread_mutex_unlock(&t->lock);
        return PATTERN_UNKNOWN;
    }
    
    double seq_ratio = (double)s->sequential_accesses / s->total_accesses;
    double reaccess_ratio = (double)s->reaccesses / s->total_accesses;
    double recent_reaccess_ratio = s->reaccesses > 0 ? 
        (double)s->recent_reaccesses / s->reaccesses : 0;
    double ws_hit_ratio = s->reaccesses > 0 ?
        (double)s->working_set_hits / s->reaccesses : 0;
    
    pthread_mutex_unlock(&t->lock);
    
    if (g_config.verbose) {
        fprintf(stdout, "[DETECT] seq=%.2f reaccess=%.2f recent_re=%.2f ws_hit=%.2f\n",
                seq_ratio, reaccess_ratio, recent_reaccess_ratio, ws_hit_ratio);
    }
    
    // Decision tree for pattern classification
    if (seq_ratio > SEQ_THRESHOLD) {
        // High sequential access
        if (reaccess_ratio < REACCESS_LOW) {
            // Pure scan pattern - FIFO
            return PATTERN_FIFO;
        } else if (reaccess_ratio < REACCESS_MED) {
            // Sequential with some re-access - S3FIFO
            return PATTERN_S3FIFO;
        }
    }
    
    // Check for MRU pattern (high recency in re-accesses)
    if (recent_reaccess_ratio > RECENCY_HIGH && reaccess_ratio > 0.2) {
        return PATTERN_MRU;
    }
    
    // Check for LRU pattern (working set with locality)
    if (ws_hit_ratio > LOCALITY_HIGH && reaccess_ratio > 0.3) {
        return PATTERN_LRU;
    }
    
    // Default to S3FIFO for mixed patterns
    return PATTERN_S3FIFO;
}

static cacheext_policy_t pattern_to_policy(pattern_type_t p) {
    switch (p) {
    case PATTERN_MRU: return CACHEEXT_POLICY_MRU;
    case PATTERN_LRU: return CACHEEXT_POLICY_MGLRU;  // Use MGLRU for LRU-like
    case PATTERN_FIFO: return CACHEEXT_POLICY_FIFO;
    case PATTERN_S3FIFO: return CACHEEXT_POLICY_S3FIFO;
    default: return CACHEEXT_POLICY_S3FIFO;
    }
}

// ============================================================================
// Policy Switching
// ============================================================================

static void log_switch(cacheext_policy_t from, cacheext_policy_t to, 
                       pattern_type_t pattern, struct pattern_stats *stats) {
    if (!g_policy_state.log_file) return;
    
    uint64_t now = now_ns();
    fprintf(g_policy_state.log_file,
            "%lu,%s,%s,%s,%lu,%.3f,%.3f,%d\n",
            (unsigned long)now,
            policy_to_string(from),
            policy_to_string(to),
            pattern_name(pattern),
            (unsigned long)stats->total_accesses,
            (double)stats->sequential_accesses / stats->total_accesses,
            (double)stats->reaccesses / stats->total_accesses,
            g_policy_state.switches_count);
    fflush(g_policy_state.log_file);
}

static int try_switch_policy(cacheext_policy_t new_policy, pattern_type_t pattern) {
    uint64_t now = now_ns();
    uint64_t elapsed_ms = (now - g_policy_state.last_switch_ns) / 1000000ULL;
    
    if (new_policy == g_policy_state.current) {
        return 0;  // Already using this policy
    }
    
    if (elapsed_ms < (uint64_t)g_config.min_switch_ms) {
        if (g_config.verbose) {
            fprintf(stdout, "[SWITCH] Skipped: too soon (elapsed=%lu ms < min=%d ms)\n",
                    (unsigned long)elapsed_ms, g_config.min_switch_ms);
        }
        return 0;
    }
    
    pthread_mutex_lock(&g_tracker.lock);
    struct pattern_stats stats_copy = g_tracker.stats;
    pthread_mutex_unlock(&g_tracker.lock);
    
    fprintf(stdout, "\n[SWITCH] %s -> %s (detected pattern: %s)\n",
            policy_to_string(g_policy_state.current),
            policy_to_string(new_policy),
            pattern_name(pattern));
    fprintf(stdout, "         Reason: seq=%.1f%% reaccess=%.1f%% events=%lu\n",
            (double)stats_copy.sequential_accesses / stats_copy.total_accesses * 100,
            (double)stats_copy.reaccesses / stats_copy.total_accesses * 100,
            (unsigned long)stats_copy.total_accesses);
    fflush(stdout);
    
    if (g_config.log_switches) {
        log_switch(g_policy_state.current, new_policy, pattern, &stats_copy);
    }
    
    if (!g_config.dry_run) {
        int rc = cache_ext(policy_to_string(new_policy),
                          g_config.cgroup_path,
                          g_config.watch_dir,
                          g_config.cgroup_size_bytes);
        if (rc != 0) {
            fprintf(stderr, "[ERROR] Policy switch failed: %d\n", rc);
            return rc;
        }
    }
    
    g_policy_state.current = new_policy;
    g_policy_state.last_switch_ns = now;
    g_policy_state.switches_count++;
    
    // Reset stats for next window
    tracker_reset_stats(&g_tracker);
    
    return 0;
}

// ============================================================================
// BPF Event Handler
// ============================================================================

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    (void)data_sz;
    
    if (g_paused || !g_running) return 0;
    
    const struct event *ev = (const struct event *)data;
    
    switch (ev->h.type) {
    case EVT_VFS_IO:
        tracker_record_access(&g_tracker,
                              ev->u.vfs_io.dev,
                              ev->u.vfs_io.ino,
                              ev->u.vfs_io.pos / 4096,  // Convert to page offset
                              ev->u.vfs_io.seq,
                              ev->u.vfs_io.rw);
        break;
        
    case EVT_FILE_FAULT:
        tracker_record_access(&g_tracker,
                              ev->u.file_fault.dev,
                              ev->u.file_fault.ino,
                              ev->u.file_fault.pgoff,
                              ev->u.file_fault.seq,
                              0);
        break;
        
    case EVT_HANDLE_MM_FAULT_RET:
        if (ev->u.fault_ret.ino != 0) {
            tracker_record_access(&g_tracker,
                                  ev->u.fault_ret.dev,
                                  ev->u.fault_ret.ino,
                                  ev->u.fault_ret.pgoff,
                                  0,
                                  0);
        }
        break;
        
    default:
        break;
    }
    
    return 0;
}

// ============================================================================
// Cgroup PID Injection
// ============================================================================

static int inject_cgroup_pids(const char *cgroup_path, int targets_fd) {
    char procs_path[PATH_MAX];
    snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", cgroup_path);
    
    FILE *fp = fopen(procs_path, "re");
    if (!fp) {
        fprintf(stderr, "[WARN] Cannot read cgroup.procs: %s\n", strerror(errno));
        return -1;
    }
    
    char line[64];
    int count = 0;
    while (fgets(line, sizeof(line), fp)) {
        unsigned long tgid = strtoul(line, NULL, 10);
        if (tgid > 0) {
            unsigned long long st0 = 0;
            if (bpf_map_update_elem(targets_fd, &tgid, &st0, BPF_ANY) == 0) {
                count++;
            }
        }
    }
    fclose(fp);
    
    if (g_config.verbose && count > 0) {
        fprintf(stdout, "[INFO] Injected %d PIDs from cgroup\n", count);
    }
    return count;
}

// ============================================================================
// Main Analysis Loop
// ============================================================================

static void *analysis_thread(void *arg) {
    (void)arg;
    
    while (g_running) {
        usleep(g_config.window_ms * 1000);
        
        if (g_paused || !g_running) continue;
        
        pattern_type_t pattern = detect_pattern(&g_tracker);
        if (pattern != PATTERN_UNKNOWN) {
            cacheext_policy_t desired = pattern_to_policy(pattern);
            try_switch_policy(desired, pattern);
        }
    }
    
    return NULL;
}

// ============================================================================
// Initialization
// ============================================================================

static int init_bpf(void) {
    libbpf_set_print(NULL);
    
    g_skel = mem_monitor_bpf__open();
    if (!g_skel) {
        fprintf(stderr, "[ERROR] Failed to open BPF skeleton\n");
        return -1;
    }
    
    // Enable only needed events
    unsigned int types_mask = (1u << EVT_VFS_IO) | 
                              (1u << EVT_FILE_FAULT) |
                              (1u << EVT_HANDLE_MM_FAULT_RET);
    
    // Disable unused programs
    if (g_skel->progs.tp_mm_vmscan_lru_shrink_inactive)
        bpf_program__set_autoload(g_skel->progs.tp_mm_vmscan_lru_shrink_inactive, false);
    if (g_skel->progs.tp_mm_page_alloc)
        bpf_program__set_autoload(g_skel->progs.tp_mm_page_alloc, false);
    if (g_skel->progs.kp_finish_fault)
        bpf_program__set_autoload(g_skel->progs.kp_finish_fault, false);
    if (g_skel->progs.krp_finish_fault)
        bpf_program__set_autoload(g_skel->progs.krp_finish_fault, false);
    if (g_skel->progs.kp_do_swap_page)
        bpf_program__set_autoload(g_skel->progs.kp_do_swap_page, false);
    if (g_skel->progs.tp_mm_thp_collapse_alloc)
        bpf_program__set_autoload(g_skel->progs.tp_mm_thp_collapse_alloc, false);
    if (g_skel->progs.tp_mm_thp_split_huge_page)
        bpf_program__set_autoload(g_skel->progs.tp_mm_thp_split_huge_page, false);
    if (g_skel->progs.tp_sched_process_exec)
        bpf_program__set_autoload(g_skel->progs.tp_sched_process_exec, false);
    if (g_skel->progs.tp_sched_process_exit)
        bpf_program__set_autoload(g_skel->progs.tp_sched_process_exit, false);
    
    int err = mem_monitor_bpf__load(g_skel);
    if (err) {
        fprintf(stderr, "[ERROR] Failed to load BPF skeleton: %d\n", err);
        mem_monitor_bpf__destroy(g_skel);
        return -1;
    }
    
    // Configure
    struct config cfg = {0};
    cfg.enable_types = types_mask;
    cfg.use_comm = 0;
    
    unsigned int k0 = 0;
    int cfg_fd = bpf_map__fd(g_skel->maps.cfg);
    if (bpf_map_update_elem(cfg_fd, &k0, &cfg, BPF_ANY) < 0) {
        fprintf(stderr, "[ERROR] Failed to configure BPF\n");
        mem_monitor_bpf__destroy(g_skel);
        return -1;
    }
    
    err = mem_monitor_bpf__attach(g_skel);
    if (err) {
        fprintf(stderr, "[ERROR] Failed to attach BPF: %d\n", err);
        mem_monitor_bpf__destroy(g_skel);
        return -1;
    }
    
    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.rb), handle_event, NULL, NULL);
    if (!g_rb) {
        fprintf(stderr, "[ERROR] Failed to create ring buffer\n");
        mem_monitor_bpf__destroy(g_skel);
        return -1;
    }
    
    return 0;
}

static void cleanup_bpf(void) {
    if (g_rb) {
        ring_buffer__free(g_rb);
        g_rb = NULL;
    }
    if (g_skel) {
        mem_monitor_bpf__destroy(g_skel);
        g_skel = NULL;
    }
}

// ============================================================================
// Main
// ============================================================================

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "\n"
        "Dynamic cache policy controller based on access pattern detection.\n"
        "\n"
        "Required:\n"
        "  -g, --cgroup PATH     Cgroup path for policy attachment\n"
        "  -w, --watch-dir DIR   Directory to monitor\n"
        "\n"
        "Optional:\n"
        "  -s, --cgroup-size N   Cgroup memory limit in bytes (for S3FIFO)\n"
        "  -m, --min-switch MS   Minimum interval between switches (default: %d)\n"
        "  -W, --window MS       Analysis window size (default: %d)\n"
        "  -o, --output DIR      Output directory for logs\n"
        "  -n, --dry-run         Detect patterns but don't switch policies\n"
        "  -v, --verbose         Verbose output\n"
        "  -h, --help            Show this help\n"
        "\n",
        prog, MIN_SWITCH_INTERVAL_MS, WINDOW_SIZE_MS);
}

int main(int argc, char **argv) {
    // Defaults
    g_config.cgroup_path = NULL;
    g_config.watch_dir = NULL;
    g_config.output_dir = "/tmp/14weeks_controller";
    g_config.cgroup_size_bytes = 256UL * 1024 * 1024;  // 256MB default
    g_config.min_switch_ms = MIN_SWITCH_INTERVAL_MS;
    g_config.window_ms = WINDOW_SIZE_MS;
    g_config.verbose = 0;
    g_config.log_switches = 1;
    g_config.dry_run = 0;
    
    static struct option long_opts[] = {
        {"cgroup", required_argument, 0, 'g'},
        {"watch-dir", required_argument, 0, 'w'},
        {"cgroup-size", required_argument, 0, 's'},
        {"min-switch", required_argument, 0, 'm'},
        {"window", required_argument, 0, 'W'},
        {"output", required_argument, 0, 'o'},
        {"dry-run", no_argument, 0, 'n'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "g:w:s:m:W:o:nvh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'g': g_config.cgroup_path = optarg; break;
        case 'w': g_config.watch_dir = optarg; break;
        case 's': g_config.cgroup_size_bytes = strtoul(optarg, NULL, 10); break;
        case 'm': g_config.min_switch_ms = atoi(optarg); break;
        case 'W': g_config.window_ms = atoi(optarg); break;
        case 'o': g_config.output_dir = optarg; break;
        case 'n': g_config.dry_run = 1; break;
        case 'v': g_config.verbose = 1; break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }
    
    if (!g_config.cgroup_path || !g_config.watch_dir) {
        fprintf(stderr, "[ERROR] --cgroup and --watch-dir are required\n");
        usage(argv[0]);
        return 1;
    }
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // Create output directory
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", g_config.output_dir);
    system(cmd);
    
    // Initialize log file
    if (g_config.log_switches) {
        char log_path[512];
        snprintf(log_path, sizeof(log_path), "%s/policy_switches.csv", g_config.output_dir);
        g_policy_state.log_file = fopen(log_path, "w");
        if (g_policy_state.log_file) {
            fprintf(g_policy_state.log_file, 
                    "timestamp_ns,from_policy,to_policy,detected_pattern,"
                    "total_accesses,seq_ratio,reaccess_ratio,switch_count\n");
            fflush(g_policy_state.log_file);
        }
    }
    
    // Initialize tracker
    if (tracker_init(&g_tracker, MAX_HISTORY_SIZE) < 0) {
        fprintf(stderr, "[ERROR] Failed to initialize tracker\n");
        return 1;
    }
    
    // Initialize BPF
    if (init_bpf() < 0) {
        tracker_destroy(&g_tracker);
        return 1;
    }
    
    // Inject cgroup PIDs
    int targets_fd = bpf_map__fd(g_skel->maps.targets);
    inject_cgroup_pids(g_config.cgroup_path, targets_fd);
    
    // Start with S3FIFO as default (good general-purpose policy)
    g_policy_state.current = CACHEEXT_POLICY_S3FIFO;
    g_policy_state.last_switch_ns = now_ns();
    
    if (!g_config.dry_run) {
        int rc = cache_ext("s3fifo", g_config.cgroup_path, 
                          g_config.watch_dir, g_config.cgroup_size_bytes);
        if (rc != 0) {
            fprintf(stderr, "[WARN] Initial policy setup failed: %d\n", rc);
        }
    }
    
    printf("\n============================================\n");
    printf("Dynamic Policy Controller Started\n");
    printf("============================================\n");
    printf("Cgroup:      %s\n", g_config.cgroup_path);
    printf("Watch dir:   %s\n", g_config.watch_dir);
    printf("Cgroup size: %lu MB\n", g_config.cgroup_size_bytes / (1024*1024));
    printf("Min switch:  %d ms\n", g_config.min_switch_ms);
    printf("Window:      %d ms\n", g_config.window_ms);
    printf("Dry run:     %s\n", g_config.dry_run ? "YES" : "NO");
    printf("Output:      %s\n", g_config.output_dir);
    printf("============================================\n\n");
    printf("Press Ctrl+C to stop.\n\n");
    fflush(stdout);
    
    // Start analysis thread
    pthread_t analysis_tid;
    pthread_create(&analysis_tid, NULL, analysis_thread, NULL);
    
    // Main polling loop
    uint64_t last_pid_inject = now_ns();
    while (g_running) {
        int rc = ring_buffer__poll(g_rb, 100);
        if (rc == -EINTR) break;
        if (rc < 0) {
            fprintf(stderr, "[ERROR] Ring buffer poll error: %d\n", rc);
            break;
        }
        
        // Periodically re-inject PIDs
        uint64_t now = now_ns();
        if (now - last_pid_inject > 2000000000ULL) {  // Every 2 seconds
            inject_cgroup_pids(g_config.cgroup_path, targets_fd);
            last_pid_inject = now;
        }
    }
    
    g_running = false;
    pthread_join(analysis_tid, NULL);
    
    // Final stats
    printf("\n============================================\n");
    printf("Controller Stopped\n");
    printf("============================================\n");
    printf("Total policy switches: %d\n", g_policy_state.switches_count);
    printf("Final policy: %s\n", policy_to_string(g_policy_state.current));
    printf("============================================\n");
    
    // Cleanup
    if (!g_config.dry_run) {
        cache_ext_shutdown();
    }
    
    if (g_policy_state.log_file) {
        fclose(g_policy_state.log_file);
    }
    
    cleanup_bpf();
    tracker_destroy(&g_tracker);
    
    return 0;
}

