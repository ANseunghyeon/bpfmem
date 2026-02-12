#ifndef _UNIFIED_METADATA_BPF_H
#define _UNIFIED_METADATA_BPF_H

/*
 * Unified Metadata for Cache Extension Policies
 * 
 * This header provides a shared metadata structure and helper functions
 * that all cache replacement policies can use. This enables:
 * 
 * 1. Seamless metadata inheritance during policy transitions
 * 2. Accurate reaccess tracking across policy changes
 * 3. Ghost entry sharing for scan-resistant detection
 * 4. Statistics collection for dynamic policy controller
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

//=============================================================================
// Policy IDs
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
// Flags for unified_folio_metadata
//=============================================================================

#define UNIFIED_FLAG_IN_MAIN      (1 << 0)  // S3FIFO: page is in main list
#define UNIFIED_FLAG_FROM_GHOST   (1 << 1)  // Page came back from ghost (reaccess)
#define UNIFIED_FLAG_INHERITED    (1 << 2)  // Page was inherited from previous policy
#define UNIFIED_FLAG_DIRTY_SKIP   (1 << 3)  // Skipped eviction due to dirty
#define UNIFIED_FLAG_ACTIVE       (1 << 4)  // MGLRU: considered active

//=============================================================================
// Unified Folio Metadata Structure
//=============================================================================

/*
 * This structure contains all fields needed by any policy.
 * Each policy uses the fields it needs and ignores the rest.
 * 
 * Note: No packed attribute - BPF requires natural alignment for atomics.
 * Size: ~80 bytes
 */
struct unified_folio_metadata {
    //=========================================================================
    // Common Fields (32 bytes)
    //=========================================================================
    u64 insert_time_ns;      // 8
    u64 last_access_ns;      // 8
    u64 access_count;        // 8
    u32 flags;               // 4
    u16 policy_id;           // 2
    u16 list_idx;            // 2
    
    //=========================================================================
    // Policy-Specific Fields (Union) - Max 24 bytes
    //=========================================================================
    union {
        // S3FIFO & MGLRU
        struct {
            u64 gen;         // 8 (MGLRU generation)
            s64 freq;        // 8 (S3FIFO frequency)
        } mglru;
        
        // LHD
        struct {
            u64 last_hit_age;      // 8
            u64 last_last_hit_age; // 8
            u32 app_class;         // 4
            u32 _pad;              // 4
        } lhd;
    } data;
    
    // Total size: 32 + 24 = 56 bytes -> fits in 64-byte cache line
    u64 _padding;            // 8 (Align to 64 bytes)
};

//=============================================================================
// Ghost Entry Structure - For detecting reaccesses after eviction
//=============================================================================

struct ghost_entry {
    u64 address_space;       // inode pointer (folio->mapping->host)
    u64 offset;              // page offset (folio->index)
};

struct ghost_metadata {
    u64 evict_time_ns;       // When the page was evicted
    u32 access_count;        // access_count at eviction time
    u16 last_policy_id;      // Policy that evicted this page
    u8  tier;                // MGLRU tier or S3FIFO list (0=small, 1=main)
    u8  reserved;
};

//=============================================================================
// Access Statistics - For dynamic policy controller
//=============================================================================

struct access_stats {
    u64 total_accesses;      // Total folio_accessed calls
    u64 reaccesses;          // Accesses where access_count was already > 0
    u64 sequential_accesses; // Sequential access pattern detected
    u64 random_accesses;     // Random access pattern detected
    u64 ghost_hits;          // Pages that came back from ghost
    u64 unique_pages;        // New unique pages added
    u64 evictions;           // Total evictions
    u64 policy_switches;     // Number of policy switches (for debugging)
};

//=============================================================================
// BPF Map Declarations - Shared across all policies
//=============================================================================

// Unified metadata map - all policies share this
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);  // folio pointer
    __type(value, struct unified_folio_metadata);
    __uint(max_entries, 4000000);
} unified_metadata_map SEC(".maps");

// Unified ghost map - for reaccess detection
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct ghost_entry);
    __type(value, struct ghost_metadata);
    __uint(max_entries, 400000);
    __uint(map_flags, BPF_F_NO_COMMON_LRU);
} unified_ghost_map SEC(".maps");

// Sequential access detection map
struct seq_detect_key {
    u32 pid;
    u64 ino;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct seq_detect_key);
    __type(value, u64); // last_index
    __uint(max_entries, 1024); // Track recent streams
} seq_detect_map SEC(".maps");

// Per-CPU access statistics
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct access_stats);
    __uint(max_entries, 1);
} access_stats_map SEC(".maps");

//=============================================================================
// Helper Functions - Metadata Operations
//=============================================================================

/*
 * Get metadata for a folio
 */
static __always_inline struct unified_folio_metadata *
unified_get_metadata(struct folio *folio)
{
    u64 key = (u64)folio;
    return bpf_map_lookup_elem(&unified_metadata_map, &key);
}

/*
 * Create new metadata for a folio
 */
static __always_inline int
unified_create_metadata(struct folio *folio, u16 policy_id, u16 list_idx)
{
    u64 key = (u64)folio;
    u64 now = bpf_ktime_get_ns();
    
    struct unified_folio_metadata meta = {
        .insert_time_ns = now,
        .last_access_ns = now,
        .access_count = 1,
        .policy_id = policy_id,
        .list_idx = list_idx,
        .flags = 0,
        .data = {0} // Zero out union fields
    };
    
    return bpf_map_update_elem(&unified_metadata_map, &key, &meta, BPF_ANY);
}

/*
 * Create metadata with initial frequency (for S3FIFO, MGLRU)
 */
static __always_inline int
unified_create_metadata_with_freq(struct folio *folio, u16 policy_id, 
                                   u16 list_idx, s64 freq)
{
    u64 key = (u64)folio;
    u64 now = bpf_ktime_get_ns();
    
    struct unified_folio_metadata meta = {
        .insert_time_ns = now,
        .last_access_ns = now,
        .access_count = 1,
        .policy_id = policy_id,
        .list_idx = list_idx,
        .flags = 0,
        .data.mglru.freq = freq,
        .data.mglru.gen = 0
    };
    
    return bpf_map_update_elem(&unified_metadata_map, &key, &meta, BPF_ANY);
}

/*
 * Delete metadata for a folio
 */
static __always_inline int
unified_delete_metadata(struct folio *folio)
{
    u64 key = (u64)folio;
    return bpf_map_delete_elem(&unified_metadata_map, &key);
}

/*
 * Record an access to a folio (updates access_count and last_access_ns)
 * Returns true if this is a reaccess (access_count was already > 1)
 * 
 * Note: access_count starts at 1 when folio is first added (via unified_create_metadata),
 * so reaccess is defined as access_count > 1 (i.e., this is at least the 2nd access).
 * 
 * BPF XADD cannot return a value, so we check access_count first,
 * then increment. This is slightly racy but acceptable for statistics.
 */
static __always_inline bool
unified_record_access(struct folio *folio)
{
    struct unified_folio_metadata *meta = unified_get_metadata(folio);
    if (!meta)
        return false;
    
    // Check if this is a reaccess BEFORE incrementing
    // access_count starts at 1, so > 1 means this is at least the 2nd access
    bool is_reaccess = (meta->access_count > 1);
    
    // Increment atomically (BPF requires not using the return value)
    __sync_fetch_and_add(&meta->access_count, 1);
    meta->last_access_ns = bpf_ktime_get_ns();
    
    return is_reaccess;
}

/*
 * Check if this folio is a reaccess (access_count > 1)
 */
static __always_inline bool
unified_is_reaccess(struct folio *folio)
{
    struct unified_folio_metadata *meta = unified_get_metadata(folio);
    return meta && meta->access_count > 1;
}

/*
 * Check if access is sequential
 */
static __always_inline bool
unified_is_sequential(struct folio *folio)
{
    if (!folio || !folio->mapping || !folio->mapping->host)
        return false;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct seq_detect_key key = {
        .pid = pid,
        .ino = (u64)folio->mapping->host->i_ino
    };
    
    u64 *last_index = bpf_map_lookup_elem(&seq_detect_map, &key);
    bool is_seq = false;
    u64 curr_index = folio->index;
    
    if (last_index) {
        // Forward sequential (Loose: accepts forward jumps/skips)
        // User confirmed <= is preferred here
        if (*last_index <= curr_index)
            is_seq = true;
        // Reverse sequential (Strict: accepts N -> N-1)
        // Captures reverse scans like stack pops
        else if (*last_index == curr_index + 1)
            is_seq = true;
    }
    
    bpf_map_update_elem(&seq_detect_map, &key, &curr_index, BPF_ANY);
    return is_seq;
}

/*
 * Get access count for a folio
 */
static __always_inline u32
unified_get_access_count(struct folio *folio)
{
    struct unified_folio_metadata *meta = unified_get_metadata(folio);
    return meta ? meta->access_count : 0;
}

//=============================================================================
// Helper Functions - Ghost Operations
//=============================================================================

/*
 * Check if a folio is in the ghost map (returns metadata pointer)
 */
static __always_inline struct ghost_metadata *
unified_lookup_ghost(struct folio *folio)
{
    if (!folio || !folio->mapping || !folio->mapping->host)
        return NULL;
        
    struct ghost_entry key = {
        .address_space = (u64)folio->mapping->host,
        .offset = folio->index,
    };
    return bpf_map_lookup_elem(&unified_ghost_map, &key);
}

/*
 * Pop ghost entry (lookup and delete)
 * Returns true if ghost entry existed, fills out the metadata
 */
static __always_inline bool
unified_pop_ghost(struct folio *folio, struct ghost_metadata *out)
{
    if (!folio || !folio->mapping || !folio->mapping->host)
        return false;
        
    struct ghost_entry key = {
        .address_space = (u64)folio->mapping->host,
        .offset = folio->index,
    };
    
    struct ghost_metadata *ghost = bpf_map_lookup_elem(&unified_ghost_map, &key);
    if (ghost) {
        if (out)
            *out = *ghost;
        bpf_map_delete_elem(&unified_ghost_map, &key);
        return true;
    }
    return false;
}

/*
 * Check if folio is in ghost and delete the entry
 * Returns true if it was in ghost
 */
static __always_inline bool
unified_check_and_delete_ghost(struct folio *folio)
{
    return unified_pop_ghost(folio, NULL);
}

/*
 * Add a folio to ghost map when evicting
 */
static __always_inline int
unified_add_ghost(struct folio *folio, u16 policy_id, u8 tier)
{
    if (!folio || !folio->mapping || !folio->mapping->host)
        return -1;
    
    struct ghost_entry key = {
        .address_space = (u64)folio->mapping->host,
        .offset = folio->index,
    };
    
    struct unified_folio_metadata *meta = unified_get_metadata(folio);
    
    struct ghost_metadata ghost = {
        .evict_time_ns = bpf_ktime_get_ns(),
        .access_count = meta ? meta->access_count : 0,
        .last_policy_id = policy_id,
        .tier = tier,
        .reserved = 0,
    };
    
    return bpf_map_update_elem(&unified_ghost_map, &key, &ghost, BPF_ANY);
}

//=============================================================================
// Helper Functions - Statistics
//=============================================================================

static __always_inline struct access_stats *
unified_get_stats(void)
{
    u32 key = 0;
    return bpf_map_lookup_elem(&access_stats_map, &key);
}

static __always_inline void
unified_stats_record_access(bool is_reaccess, bool is_sequential)
{
    struct access_stats *stats = unified_get_stats();
    if (!stats)
        return;
    
    __sync_fetch_and_add(&stats->total_accesses, 1);
    
    if (is_reaccess)
        __sync_fetch_and_add(&stats->reaccesses, 1);
    
    if (is_sequential)
        __sync_fetch_and_add(&stats->sequential_accesses, 1);
    else
        __sync_fetch_and_add(&stats->random_accesses, 1);
}

static __always_inline void
unified_stats_record_ghost_hit(void)
{
    struct access_stats *stats = unified_get_stats();
    if (stats)
        __sync_fetch_and_add(&stats->ghost_hits, 1);
}

static __always_inline void
unified_stats_record_unique_page(void)
{
    struct access_stats *stats = unified_get_stats();
    if (stats)
        __sync_fetch_and_add(&stats->unique_pages, 1);
}

static __always_inline void
unified_stats_record_eviction(void)
{
    struct access_stats *stats = unified_get_stats();
    if (stats)
        __sync_fetch_and_add(&stats->evictions, 1);
}

//=============================================================================
// Helper Functions - Policy Transition
//=============================================================================

/*
 * Update metadata for policy transition
 * Called during inheritance to adapt metadata to new policy
 */
static __always_inline void
unified_transition_to_policy(struct folio *folio, u16 new_policy_id)
{
    struct unified_folio_metadata *meta = unified_get_metadata(folio);
    if (!meta)
        return;
    
    meta->policy_id = new_policy_id;
    meta->flags |= UNIFIED_FLAG_INHERITED;
}

/*
 * Convert access_count to S3FIFO frequency (0-3)
 */
static __always_inline s64
unified_access_count_to_freq(u32 access_count)
{
    if (access_count >= 3)
        return 3;
    return (s64)access_count;
}

/*
 * Convert access_count to MGLRU tier (0-3)
 */
static __always_inline int
unified_access_count_to_tier(u32 access_count)
{
    if (access_count <= 1)
        return 0;
    else if (access_count <= 3)
        return 1;
    else if (access_count <= 7)
        return 2;
    else
        return 3;
}

#endif /* _UNIFIED_METADATA_BPF_H */
