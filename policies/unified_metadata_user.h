/*
 * unified_metadata_user.h
 * 
 * Userspace header for accessing unified metadata BPF maps.
 * Used by dynamic_policy_controller to read access statistics.
 */

#ifndef _UNIFIED_METADATA_USER_H
#define _UNIFIED_METADATA_USER_H

#include <stdint.h>
#include <stdbool.h>

//=============================================================================
// Policy IDs (must match unified_metadata.bpf.h)
//=============================================================================

#define POLICY_ID_NONE      0
#define POLICY_ID_FIFO      1
#define POLICY_ID_MRU       2
#define POLICY_ID_S3FIFO    3
#define POLICY_ID_LHD       4
#define POLICY_ID_MGLRU     5
#define POLICY_ID_SAMPLING  6
#define POLICY_ID_GET_SCAN  7

//=============================================================================
// Access Statistics Structure (must match unified_metadata.bpf.h)
//=============================================================================

struct access_stats {
    uint64_t total_accesses;      // Total folio_accessed calls
    uint64_t reaccesses;          // Accesses where access_count was already > 0
    uint64_t sequential_accesses; // Sequential access pattern detected
    uint64_t random_accesses;     // Random access pattern detected
    uint64_t ghost_hits;          // Pages that came back from ghost
    uint64_t unique_pages;        // New unique pages added
    uint64_t evictions;           // Total evictions
    uint64_t policy_switches;     // Number of policy switches
};

//=============================================================================
// BPF Map Names
//=============================================================================

#define UNIFIED_METADATA_MAP_NAME     "unified_metadata_map"
#define UNIFIED_GHOST_MAP_NAME        "unified_ghost_map"
#define ACCESS_STATS_MAP_NAME         "access_stats_map"

//=============================================================================
// Helper Functions for Userspace
//=============================================================================

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/*
 * Read access statistics from BPF map.
 * Returns 0 on success, negative error code on failure.
 * 
 * Note: access_stats_map is a per-CPU array, so we need to aggregate
 * across all CPUs.
 */
static inline int read_access_stats(int map_fd, struct access_stats *out)
{
    if (map_fd < 0 || !out)
        return -1;

    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus < 0)
        return num_cpus;

    struct access_stats *percpu_stats = calloc(num_cpus, sizeof(struct access_stats));
    if (!percpu_stats)
        return -ENOMEM;

    uint32_t key = 0;
    int err = bpf_map_lookup_elem(map_fd, &key, percpu_stats);
    if (err) {
        free(percpu_stats);
        return err;
    }

    // Aggregate across CPUs
    memset(out, 0, sizeof(*out));
    for (int i = 0; i < num_cpus; i++) {
        out->total_accesses += percpu_stats[i].total_accesses;
        out->reaccesses += percpu_stats[i].reaccesses;
        out->sequential_accesses += percpu_stats[i].sequential_accesses;
        out->random_accesses += percpu_stats[i].random_accesses;
        out->ghost_hits += percpu_stats[i].ghost_hits;
        out->unique_pages += percpu_stats[i].unique_pages;
        out->evictions += percpu_stats[i].evictions;
        out->policy_switches += percpu_stats[i].policy_switches;
    }

    free(percpu_stats);
    return 0;
}

/*
 * Calculate reaccess ratio from access statistics.
 */
static inline double calc_reaccess_ratio(const struct access_stats *stats)
{
    if (!stats || stats->total_accesses == 0)
        return 0.0;
    return (double)stats->reaccesses / stats->total_accesses;
}

/*
 * Calculate ghost hit ratio (scan-resistant indicator).
 * Uses total_accesses as denominator to represent the fraction of
 * accesses that are refaults. This is robust against unique_pages being 0
 * (e.g. in a looping scan where all pages are ghosts).
 */
static inline double calc_ghost_hit_ratio(const struct access_stats *stats)
{
    if (!stats || stats->total_accesses == 0)
        return 0.0;
    return (double)stats->ghost_hits / stats->total_accesses;
}

/*
 * Calculate sequential ratio.
 */
static inline double calc_sequential_ratio(const struct access_stats *stats)
{
    if (!stats || stats->total_accesses == 0)
        return 0.0;
    return (double)stats->sequential_accesses / stats->total_accesses;
}

/*
 * Get access statistics delta between two samples.
 */
static inline void calc_stats_delta(const struct access_stats *prev,
                                    const struct access_stats *curr,
                                    struct access_stats *delta)
{
    if (!prev || !curr || !delta)
        return;

    delta->total_accesses = curr->total_accesses - prev->total_accesses;
    delta->reaccesses = curr->reaccesses - prev->reaccesses;
    delta->sequential_accesses = curr->sequential_accesses - prev->sequential_accesses;
    delta->random_accesses = curr->random_accesses - prev->random_accesses;
    delta->ghost_hits = curr->ghost_hits - prev->ghost_hits;
    delta->unique_pages = curr->unique_pages - prev->unique_pages;
    delta->evictions = curr->evictions - prev->evictions;
    delta->policy_switches = curr->policy_switches - prev->policy_switches;
}

/*
 * Print access statistics for debugging.
 */
static inline void print_access_stats(const struct access_stats *stats, FILE *fp)
{
    if (!stats || !fp)
        return;

    fprintf(fp, "Access Statistics:\n");
    fprintf(fp, "  Total accesses:      %lu\n", stats->total_accesses);
    fprintf(fp, "  Reaccesses:          %lu (%.2f%%)\n", 
            stats->reaccesses,
            stats->total_accesses > 0 ? 
                (double)stats->reaccesses / stats->total_accesses * 100 : 0);
    fprintf(fp, "  Sequential:          %lu\n", stats->sequential_accesses);
    fprintf(fp, "  Random:              %lu\n", stats->random_accesses);
    fprintf(fp, "  Ghost hits:          %lu\n", stats->ghost_hits);
    fprintf(fp, "  Unique pages:        %lu\n", stats->unique_pages);
    fprintf(fp, "  Evictions:           %lu\n", stats->evictions);
    fprintf(fp, "  Policy switches:     %lu\n", stats->policy_switches);
}

#endif /* _UNIFIED_METADATA_USER_H */
