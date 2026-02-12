#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"
#include "unified_metadata.bpf.h"

char _license[] SEC("license") = "GPL";

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define INT64_MAX (9223372036854775807LL)

// #define DEBUG
#ifdef DEBUG
#define dbg_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define dbg_printk(fmt, ...)
#endif

#define ENOENT		2  /* include/uapi/asm-generic/errno-base.h */

// Note: BPF atomic operations have restrictions:
// 1. XADD return value cannot be used
// 2. Only 64-bit atomics are supported
// For simple reads/writes of aligned 64-bit values, use direct access.
#define atomic_long_read(ptr) (*(volatile typeof(*(ptr)) *)(ptr))
#define atomic_long_zero(ptr) do { *(ptr) = 0; } while(0)
#define atomic_long_store(ptr, val) do { *(ptr) = (val); } while(0)

#define DEFINE_MIN_SEQ(lrugen) \
	unsigned long min_seq = READ_ONCE(lrugen->min_seq)
#define DEFINE_MAX_SEQ(lrugen) \
	unsigned long max_seq = READ_ONCE(lrugen->max_seq)

////////////////////////////////////////////////////////////////////////////////////
//  MGLRU Constants and Data Structures
////////////////////////////////////////////////////////////////////////////////////

#define MAX_NR_TIERS 4
#define MIN_NR_GENS 2
#define MAX_NR_GENS 4
#define NR_HIST_GENS 1
#define MIN_LRU_BATCH 64

// Global policy metadata
struct mglru_global_metadata {
	struct bpf_spin_lock lock;
	unsigned long max_seq;
	unsigned long min_seq;
	s64 evicted[MAX_NR_TIERS];
	s64 refaulted[MAX_NR_TIERS];
	s64 tier_selected[MAX_NR_TIERS];
	s64 success_evicted;
	s64 failed_evicted;
	unsigned long avg_refaulted[MAX_NR_TIERS];
	unsigned long avg_total[MAX_NR_TIERS];
	unsigned long protected[MAX_NR_TIERS - 1];
	long nr_pages[MAX_NR_GENS];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct mglru_global_metadata);
	__uint(max_entries, 1);
} mglru_global_metadata_map SEC(".maps");

#define DEFINE_LRUGEN_void                                                     \
	struct mglru_global_metadata *lrugen;                                  \
	int key__ = 0;                                                         \
	lrugen = bpf_map_lookup_elem(&mglru_global_metadata_map, &key__);      \
	if (!lrugen) {                                                         \
		bpf_printk(                                                    \
			"cache_ext: Failed to lookup lrugen metadata\n"); \
		return;                                                        \
	}

#define DEFINE_LRUGEN_int                                                      \
	struct mglru_global_metadata *lrugen;                                  \
	int key__ = 0;                                                         \
	lrugen = bpf_map_lookup_elem(&mglru_global_metadata_map, &key__);      \
	if (!lrugen) {                                                         \
		bpf_printk(                                                    \
			"cache_ext: Failed to lookup lrugen metadata\n"); \
		return -1;                                                     \
	}

#define DEFINE_LRUGEN_bool                                                     \
	struct mglru_global_metadata *lrugen;                                  \
	int key__ = 0;                                                         \
	lrugen = bpf_map_lookup_elem(&mglru_global_metadata_map, &key__);      \
	if (!lrugen) {                                                         \
		bpf_printk(                                                    \
			"cache_ext: Failed to lookup lrugen metadata\n"); \
		return false;                                                  \
	}

#define assert_valid_tier_0(tier_idx)                                 \
	if (tier_idx < 0 || tier_idx >= MAX_NR_TIERS) {               \
		bpf_printk("cache_ext: Invalid tier index %d\n", \
			   tier_idx);                                 \
		return;                                               \
	}

#define assert_valid_gen_0(gen_idx)                                            \
	if (gen_idx < 0 || gen_idx >= MAX_NR_GENS) {                           \
		bpf_printk("cache_ext: Invalid gen index %d\n", gen_idx); \
		return;                                                        \
	}

#define assert_valid_tier_1(tier_idx)                                 \
	if (tier_idx < 0 || tier_idx >= MAX_NR_TIERS) {               \
		bpf_printk("cache_ext: Invalid tier index %d\n", \
			   tier_idx);                                 \
		return -1;                                            \
	}

#define assert_valid_gen_1(gen_idx)                                            \
	if (gen_idx < 0 || gen_idx >= MAX_NR_GENS) {                           \
		bpf_printk("cache_ext: Invalid gen index %d\n", gen_idx); \
		return -1;                                                     \
	}

inline void update_refaulted_stat(struct mglru_global_metadata *lrugen, int tier_idx,
			   s64 delta)
{
	// Masking to help verifier prove bounds (MAX_NR_TIERS is 4)
	tier_idx &= (MAX_NR_TIERS - 1);
	__sync_fetch_and_add(&lrugen->refaulted[tier_idx], delta);
}

inline void update_evicted_stat(struct mglru_global_metadata *lrugen, int tier_idx,
			 s64 delta)
{
	tier_idx &= (MAX_NR_TIERS - 1);
	__sync_fetch_and_add(&lrugen->evicted[tier_idx], delta);
}

inline void update_nr_pages_stat(struct mglru_global_metadata *lrugen, unsigned int gen_idx,
			  s64 delta)
{
	// MAX_NR_GENS is 4
	gen_idx &= (MAX_NR_GENS - 1);
	__sync_fetch_and_add(&lrugen->nr_pages[gen_idx], delta);
}

inline void update_tier_selected_stat(struct mglru_global_metadata *lrugen, int tier_idx,
			  s64 delta)
{
	tier_idx &= (MAX_NR_TIERS - 1);
	__sync_fetch_and_add(&lrugen->tier_selected[tier_idx], delta);
}


inline s64 read_refaulted_stat(struct mglru_global_metadata *lrugen, int tier_idx)
{
	assert_valid_tier_1(tier_idx);
	return max(0, atomic_long_read(&lrugen->refaulted[tier_idx]));
}

inline s64 read_evicted_stat(struct mglru_global_metadata *lrugen, int tier_idx)
{
	assert_valid_tier_1(tier_idx);
	return max(0, atomic_long_read(&lrugen->evicted[tier_idx]));
}

inline s64 read_nr_pages_stat(struct mglru_global_metadata *lrugen, unsigned int gen_idx)
{
	assert_valid_gen_1(gen_idx);
	return max(0, atomic_long_read(&lrugen->nr_pages[gen_idx]));
}

inline void update_protected_stat(struct mglru_global_metadata *lrugen, int tier_idx,
			   s64 delta)
{
	__sync_fetch_and_add(&lrugen->protected[tier_idx - 1], delta);
}

// Gen lists
static __u64 mglru_lists[MAX_NR_GENS];
static volatile bool mglru_initialized = false;

/******************************************************************************
 *                          PID controller
 ******************************************************************************/

 struct ctrl_pos___x {
	unsigned long refaulted;
	unsigned long total;
	int gain;
};

static inline void read_ctrl_pos(struct mglru_global_metadata *lrugen, int tier,
			  int gain, struct ctrl_pos___x *pos)
{
	pos->refaulted = lrugen->avg_refaulted[tier] +
			 __sync_fetch_and_add(&lrugen->refaulted[tier], 0);
	pos->total = lrugen->avg_total[tier] +
		     __sync_fetch_and_add(&lrugen->evicted[tier], 0);
	if (tier)
		pos->total += lrugen->protected[tier - 1];
	pos->gain = gain;
}

static inline void reset_ctrl_pos(struct mglru_global_metadata *lrugen, bool carryover)
{
	int tier;
	bool clear = carryover ? NR_HIST_GENS == 1 : NR_HIST_GENS > 1;

	if (!carryover && !clear)
		return;

	for (tier = 0; tier < MAX_NR_TIERS; tier++) {
		if (carryover) {
			unsigned long sum;

			sum = lrugen->avg_refaulted[tier] +
			      atomic_long_read(&lrugen->refaulted[tier]);
			WRITE_ONCE(lrugen->avg_refaulted[tier], sum / 2);

			sum = lrugen->avg_total[tier] +
			      atomic_long_read(&lrugen->evicted[tier]);
			if (tier)
				sum += lrugen->protected[tier - 1];
			WRITE_ONCE(lrugen->avg_total[tier], sum / 2);
		}

		if (clear) {
			atomic_long_zero(&lrugen->refaulted[tier]);
			atomic_long_zero(&lrugen->evicted[tier]);
			if (tier)
				WRITE_ONCE(lrugen->protected[tier - 1], 0);
		}
	}
}

static inline bool positive_ctrl_err(struct ctrl_pos___x *sp, struct ctrl_pos___x *pv)
{
	return pv->refaulted < MIN_LRU_BATCH ||
	       pv->refaulted * (sp->total + MIN_LRU_BATCH) * sp->gain <=
		       (sp->refaulted + 1) * pv->total * pv->gain;
}

static inline int get_tier_idx(struct mglru_global_metadata *lrugen)
{
	int tier;
	struct ctrl_pos___x sp, pv;

	read_ctrl_pos(lrugen, 0, 1, &sp);
	for (tier = 1; tier < MAX_NR_TIERS; tier++) {
		read_ctrl_pos(lrugen, tier, 2, &pv);
		if (!positive_ctrl_err(&sp, &pv))
			break;
	}

	return tier - 1;
}

static inline void folio_inc_refs(struct folio *folio)
{
	struct unified_folio_metadata *metadata = unified_get_metadata(folio);
	if (!metadata) {
		bpf_printk("cache_ext: Tried to inc refs but folio not found in map.\n");
		return;
	}
	__sync_fetch_and_add(&metadata->data.mglru.freq, 1);
}

static inline int folio_lru_refs(struct folio *folio)
{
	struct unified_folio_metadata *metadata = unified_get_metadata(folio);
	if (!metadata)
		return -1;

	return atomic_long_read(&metadata->data.mglru.freq);
}

static inline unsigned int lru_gen_from_seq(unsigned long seq)
{
	return seq % MAX_NR_GENS;
}

static inline bool folio_test_active(struct folio *folio)
{
	return folio_lru_refs(folio) >= 2;
}

static inline int order_base_2(int n)
{
	if (n <= 1) {
		return 0;
	} else if (n <= 3) {
		return 1;
	} else if (n <= 7) {
		return 2;
	} else if (n <= 8) {
		return 3;
	}
	return 3;
}

static inline int lru_tier_from_refs(int refs)
{
	return order_base_2(refs);
}

static inline bool gen_within_limits(unsigned int gen)
{
	return 0 <= gen && gen <= MAX_NR_GENS;
}

static inline int get_nr_gens(struct mglru_global_metadata *lrugen)
{
	return lrugen->max_seq - lrugen->min_seq + 1;
}

static inline bool gen_almost_empty(struct mglru_global_metadata *lrugen,
				    int min_seq)
{
	int oldest_gen = lru_gen_from_seq(min_seq);
	int nr_folios = read_nr_pages_stat(lrugen, oldest_gen);
	int threshold = 4;
	return nr_folios <= threshold;
}

static inline bool lru_gen_add_folio(struct folio *folio, struct ghost_metadata *ghost)
{
	unsigned long seq;
	if (folio_test_unevictable(folio)) {
		bpf_printk("cache_ext: Unevictable folio\n");
		return false;
	}

	DEFINE_LRUGEN_bool;
	DEFINE_MIN_SEQ(lrugen);
	DEFINE_MAX_SEQ(lrugen);

	if (folio_test_active(folio))
		seq = max_seq;
	else if ((folio_test_reclaim(folio) &&
		  (folio_test_dirty(folio) || folio_test_writeback(folio))))
		seq = max_seq - 1;
	else if (min_seq + MIN_NR_GENS >= max_seq)
		seq = min_seq;
	else
		seq = min_seq + 1;

	unsigned int gen = lru_gen_from_seq(seq);
	if (!gen_within_limits(gen)) {
		bpf_printk("cache_ext: Invalid gen %d (min_seq=%lu, max_seq=%lu)\n",
			gen, min_seq, max_seq);
		return false;
	}

	// Create unified metadata
	if (unified_create_metadata_with_freq(folio, POLICY_ID_MGLRU, gen, 1)) {
		bpf_printk("cache_ext: Failed to save folio metadata\n");
		return false;
	}
	
	struct unified_folio_metadata *meta = unified_get_metadata(folio);
	if (!meta) {
		return false;
	}
	meta->data.mglru.gen = gen;
	
	if (ghost) {
		meta->flags |= UNIFIED_FLAG_FROM_GHOST;
		
		// Restore access count from ghost to preserve history
		// This ensures refaults are eventually counted as reaccesses
		if (ghost->access_count > 0) {
			meta->access_count = ghost->access_count;
		}
		
		update_refaulted_stat(lrugen, ghost->tier, 1);
		unified_stats_record_ghost_hit();
	} else {
		unified_stats_record_unique_page();
	}
	
	update_nr_pages_stat(lrugen, gen, folio_nr_pages(folio));

	int ret = bpf_cache_ext_list_add(mglru_lists[gen], folio);
	if (ret != 0) {
		bpf_printk("cache_ext: Failed to add folio to mglru_lists[%d]\n", gen);
		unified_delete_metadata(folio);
		return false;
	}

	return true;
}

static inline bool should_run_aging(struct mglru_global_metadata *lrugen,
				    unsigned long max_seq)
{
	unsigned int gen;
	unsigned long old = 0;
	unsigned long young = 0;
	unsigned long total = 0;
	DEFINE_MIN_SEQ(lrugen);

	if (min_seq + MIN_NR_GENS > max_seq) {
		return true;
	}

	unsigned long seq;
	int max_iter = min(MAX_NR_GENS, max_seq - min_seq);
	for (int i = 0; i < max_iter; i++) {
		seq = min_seq + i;
		unsigned long size = 0;

		gen = lru_gen_from_seq(seq);

		size += max(read_nr_pages_stat(lrugen, gen), 0L);

		total += size;
		if (seq == max_seq)
			young += size;
		else if (seq + MIN_NR_GENS == max_seq)
			old += size;
	}

	if (min_seq + MIN_NR_GENS < max_seq)
		return false;

	if (young * MIN_NR_GENS > total)
		return true;
	if (old * (MIN_NR_GENS + 2) < total)
		return true;

	return false;
}

static inline bool try_to_inc_min_seq(struct mglru_global_metadata *lrugen)
{
	DEFINE_MIN_SEQ(lrugen);
	if (!gen_almost_empty(lrugen, min_seq)) {
		return false;
	}
	WRITE_ONCE(lrugen->min_seq, lrugen->min_seq + 1);
	reset_ctrl_pos(lrugen, true);
	return true;
}

static inline bool try_to_inc_max_seq(struct mglru_global_metadata *lrugen)
{
	if (get_nr_gens(lrugen) == MAX_NR_GENS) {
		int ret = try_to_inc_min_seq(lrugen);
		if (!ret) {
			return false;
		}
	}

	reset_ctrl_pos(lrugen, false);

	WRITE_ONCE(lrugen->max_seq, lrugen->max_seq + 1);
	return true;
}

////////////////////////////////////////////////////////////
//   CACHE_EXT Hooks
////////////////////////////////////////////////////////////

struct eviction_metadata {
	__u64 curr_gen;
	__u64 next_gen;
	__u64 iter_reached;
	__u64 tier_threshold;
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct eviction_metadata);
} mglru_percpu_array SEC(".maps");


struct eviction_metadata * get_eviction_metadata() {
	u32 key = 0;
	return bpf_map_lookup_elem(&mglru_percpu_array, &key);
}

void set_eviction_metadata(struct eviction_metadata *eviction_meta) {
	u32 key = 0;
	int ret = bpf_map_update_elem(&mglru_percpu_array, &key, eviction_meta, BPF_ANY);
	if (ret < 0) {
		bpf_printk("cache_ext: Failed to update eviction metadata\n");
	}
}

inline bool is_folio_relevant(struct folio *folio)
{
	if (!folio) {
		return false;
	}
	if (folio->mapping == NULL) {
		return false;
	}
	if (folio->mapping->host == NULL) {
		return false;
	}
	bool res = inode_in_watchlist(folio->mapping->host->i_ino);
	return res;
}

/*
 * Callback for inherit_iterate: convert inherited pages to MGLRU metadata
 */
static int mglru_inherit_callback(int idx, struct cache_ext_list_node *node)
{
	struct mglru_global_metadata *lrugen;
	int key__ = 0;
	lrugen = bpf_map_lookup_elem(&mglru_global_metadata_map, &key__);
	if (!lrugen)
		return 2;

	DEFINE_MAX_SEQ(lrugen);
	
	struct unified_folio_metadata *meta = unified_get_metadata(node->folio);
	
	if (!meta) {
		// Create new metadata for inherited page
		if (unified_create_metadata_with_freq(node->folio, POLICY_ID_MGLRU, 0, 1)) {
			return 2;  // Skip if we can't create metadata
		}
		meta = unified_get_metadata(node->folio);
		if (!meta)
			return 2;
	}
	
	// Convert to MGLRU metadata
	meta->policy_id = POLICY_ID_MGLRU;
	meta->flags |= UNIFIED_FLAG_INHERITED;
	
	// Determine generation based on access_count
	u32 target_gen;
	if (meta->access_count >= 3) {
		target_gen = lru_gen_from_seq(max_seq);  // youngest
		meta->flags |= UNIFIED_FLAG_ACTIVE;
	} else if (meta->access_count >= 2) {
		target_gen = lru_gen_from_seq(max_seq - 1);
	} else {
		target_gen = lru_gen_from_seq(lrugen->min_seq);  // oldest
	}
	
	meta->data.mglru.gen = target_gen;
	meta->data.mglru.freq = meta->access_count;  // Use access_count as refs
	
	// Check ghost for refault tracking
	struct ghost_metadata ghost;
	if (unified_pop_ghost(node->folio, &ghost)) {
		meta->flags |= UNIFIED_FLAG_FROM_GHOST;
		update_refaulted_stat(lrugen, ghost.tier, 1);
	}
	
	update_nr_pages_stat(lrugen, target_gen, 1);
	
	// Return generation index to move to the correct list
	// Note: inherit_iterate moves to target_list, we handle lists in init
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(mglru_init, struct mem_cgroup *memcg)
{
	bpf_printk("cache_ext: MGLRU init starting, memcg=%p\n", memcg);

	DEFINE_LRUGEN_int;
	WRITE_ONCE(lrugen->max_seq, MIN_NR_GENS + 1);
	
	for (int i = 0; i < MAX_NR_GENS; i++) {
		__u64 list_ptr = bpf_cache_ext_ds_registry_new_list(memcg);
		if (list_ptr == 0) {
			bpf_printk("cache_ext: Failed to allocate list for gen %d\n", i);
			return -1;
		}
		mglru_lists[i] = list_ptr;
	}

	// Check for inherited pages
	bool has_pages = bpf_cache_ext_inherit_has_pages(memcg);
	u64 inherit_count = bpf_cache_ext_inherit_get_count(memcg);
	bpf_printk("cache_ext: MGLRU inherit check: has_pages=%d, count=%llu\n",
		   has_pages, inherit_count);

	if (has_pages && inherit_count > 0) {
		bpf_printk("cache_ext: MGLRU inheriting %llu pages\n", inherit_count);
		
		// Inherit to gen 0 (oldest), callback will set proper generation
		int processed = bpf_cache_ext_inherit_iterate(
			memcg,
			mglru_lists[0],
			mglru_inherit_callback,
			0
		);
		
		bpf_printk("cache_ext: MGLRU actually inherited %d pages\n", processed);
	}

	mglru_initialized = true;
	bpf_printk("cache_ext: MGLRU init complete\n");

	return 0;
}


// MGLRU iteration function
static int mglru_iter_fn(int idx, struct cache_ext_list_node *a)
{
	struct mglru_global_metadata *lrugen;
	int key__ = 0;
	lrugen = bpf_map_lookup_elem(&mglru_global_metadata_map, &key__);
	if (!lrugen) {
		bpf_printk("cache_ext: Failed to lookup lrugen metadata\n");
		return CACHE_EXT_EVICT_NODE;
	}

	struct eviction_metadata *eviction_meta = get_eviction_metadata();
	if (!eviction_meta) {
		bpf_printk("cache_ext: iter_fn: Failed to get eviction metadata\n");
		return CACHE_EXT_EVICT_NODE;
	}
	eviction_meta->iter_reached = idx;

	// Get folio metadata
	struct unified_folio_metadata *meta = unified_get_metadata(a->folio);
	if (!meta) {
		bpf_printk("cache_ext: iter_fn: Failed to get metadata\n");
		return CACHE_EXT_EVICT_NODE;
	}

	int tier_threshold = eviction_meta->tier_threshold;
	if (tier_threshold > MAX_NR_TIERS || tier_threshold < 0) {
		bpf_printk("cache_ext: Invalid tier threshold %d\n", tier_threshold);
	}
	
	int tier = lru_tier_from_refs(atomic_long_read(&meta->data.mglru.freq));

	/* protected */
	if (tier > tier_threshold) {
		update_protected_stat(lrugen, tier, folio_nr_pages(a->folio));
		// promote to next gen
		int num_pages = folio_nr_pages(a->folio);
		update_nr_pages_stat(lrugen, eviction_meta->curr_gen, -num_pages);
		update_nr_pages_stat(lrugen, eviction_meta->next_gen, num_pages);
		atomic_long_store(&meta->data.mglru.gen, eviction_meta->next_gen);
		return CACHE_EXT_CONTINUE_ITER;
	}

	/* waiting for writeback */
	if (folio_test_locked(a->folio) || folio_test_writeback(a->folio) ||
	    folio_test_dirty(a->folio)) {
		// promote to next gen
		int num_pages = folio_nr_pages(a->folio);
		update_nr_pages_stat(lrugen, eviction_meta->curr_gen, -num_pages);
		update_nr_pages_stat(lrugen, eviction_meta->next_gen, num_pages);
		atomic_long_store(&meta->data.mglru.gen, eviction_meta->next_gen);
		return CACHE_EXT_CONTINUE_ITER;
	}
	return CACHE_EXT_EVICT_NODE;
}

void BPF_STRUCT_OPS(mglru_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	if (!mglru_initialized)
		return;

	DEFINE_LRUGEN_void;

	bool inc_max_seq_failed = false;
	bpf_spin_lock(&lrugen->lock);
	DEFINE_MIN_SEQ(lrugen);
	DEFINE_MAX_SEQ(lrugen);
	if (should_run_aging(lrugen, max_seq)) {
		if (!try_to_inc_max_seq(lrugen)){
			inc_max_seq_failed = true;
		}
	}
	if (max_seq - min_seq > MIN_NR_GENS)
		try_to_inc_min_seq(lrugen);
	// Read min/max seq again
	min_seq = READ_ONCE(lrugen->min_seq);
	max_seq = READ_ONCE(lrugen->max_seq);
	int oldest_gen = lru_gen_from_seq(min_seq);
	volatile unsigned int next_gen = (oldest_gen + 1) % MAX_NR_GENS;
	bpf_spin_unlock(&lrugen->lock);

	if (inc_max_seq_failed) {
		bpf_printk("cache_ext: Failed to increment max_seq\n");
	}

	int tier_threshold = get_tier_idx(lrugen);
	update_tier_selected_stat(lrugen, tier_threshold, 1);

	// Save eviction metadata for stats
	struct eviction_metadata ev_meta = {
		.curr_gen = oldest_gen,
		.next_gen = next_gen,
		.tier_threshold = tier_threshold,
	};
	set_eviction_metadata(&ev_meta);

	assert_valid_gen_0(next_gen);

	__u64 next_gen_list = mglru_lists[next_gen];
	__u64 oldest_gen_list = mglru_lists[oldest_gen];
	struct cache_ext_iterate_opts opts = {
		.continue_list = next_gen_list,
		.continue_mode = CACHE_EXT_ITERATE_TAIL,
		.evict_list = CACHE_EXT_ITERATE_SELF,
		.evict_mode = CACHE_EXT_ITERATE_TAIL,
	};


	int ret = bpf_cache_ext_list_iterate_extended(
		memcg, oldest_gen_list, mglru_iter_fn, &opts, eviction_ctx);
	if (ret < 0) {
		bpf_printk("cache_ext: Failed to iterate list\n");
		return;
	}
	struct eviction_metadata *eviction_meta = get_eviction_metadata();
	if (eviction_meta == NULL) return;
	if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
		min_seq = READ_ONCE(lrugen->min_seq);
		oldest_gen = lru_gen_from_seq(min_seq);
		next_gen = (oldest_gen + 1) % MAX_NR_GENS;
		__u64 next_gen_list = mglru_lists[next_gen];
		__u64 oldest_gen_list = mglru_lists[oldest_gen];
		struct cache_ext_iterate_opts opts = {
			.continue_list = next_gen_list,
			.continue_mode = CACHE_EXT_ITERATE_TAIL,
			.evict_list = CACHE_EXT_ITERATE_SELF,
			.evict_mode = CACHE_EXT_ITERATE_TAIL,
		};
		int ret = bpf_cache_ext_list_iterate_extended(
			memcg, oldest_gen_list, mglru_iter_fn, &opts, eviction_ctx);
		if (ret < 0) {
			bpf_printk("cache_ext: Failed to iterate list\n");
			return;
		}
	}
	s64 success_evicted = eviction_ctx->nr_folios_to_evict;
	s64 failed_evicted = max(0, eviction_ctx->request_nr_folios_to_evict - eviction_ctx->nr_folios_to_evict);
	__sync_fetch_and_add(&lrugen->failed_evicted, failed_evicted);
	__sync_fetch_and_add(&lrugen->success_evicted, success_evicted);
	if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
		bpf_printk("cache_ext: Failed to evict requested number of folios: %d/%d. Used list idx %d, list ptr: %p. Iter reached: %d\n",
				eviction_ctx->nr_folios_to_evict,
				eviction_ctx->request_nr_folios_to_evict,
				oldest_gen,
				oldest_gen_list,
				eviction_meta->iter_reached);
	}
}

void BPF_STRUCT_OPS(mglru_folio_added, struct folio *folio)
{
	if (!mglru_initialized)
		return;

	if (!is_folio_relevant(folio)) {
		return;
	}
	
	// Check ghost for refault detection
	struct ghost_metadata ghost_val;
	struct ghost_metadata *ghost_ptr = NULL;
	
	if (unified_pop_ghost(folio, &ghost_val)) {
		ghost_ptr = &ghost_val;
	}
	
	lru_gen_add_folio(folio, ghost_ptr);
}

void BPF_STRUCT_OPS(mglru_folio_accessed, struct folio *folio)
{
	if (!mglru_initialized)
		return;

	if (!is_folio_relevant(folio)) {
		return;
	}
	
	// Record access for reaccess tracking
	bool is_reaccess = unified_record_access(folio);
	unified_stats_record_access(is_reaccess, unified_is_sequential(folio));
	
	folio_inc_refs(folio);
}

void BPF_STRUCT_OPS(mglru_folio_evicted, struct folio *folio)
{
	if (!mglru_initialized)
		return;

	if (!is_folio_relevant(folio)) {
		return;
	}
	DEFINE_LRUGEN_void;

	// Get metadata before eviction
	struct unified_folio_metadata *metadata = unified_get_metadata(folio);
	if (!metadata) {
		bpf_printk("cache_ext: Tried to delete folio metadata but not found in map.\n");
		return;
	}
	
	// Add ghost entry for refault detection
	int tier = lru_tier_from_refs(atomic_long_read(&metadata->data.mglru.freq));
	unified_add_ghost(folio, POLICY_ID_MGLRU, tier);
	unified_stats_record_eviction();

	// Update generation page count
	update_evicted_stat(lrugen, tier, 1);
	update_nr_pages_stat(lrugen, metadata->data.mglru.gen, -folio_nr_pages(folio));

	// Delete metadata
	unified_delete_metadata(folio);
}

SEC(".struct_ops.link")
struct cache_ext_ops mglru_ops = {
	.init = (void *)mglru_init,
	.evict_folios = (void *)mglru_evict_folios,
	.folio_accessed = (void *)mglru_folio_accessed,
	.folio_evicted = (void *)mglru_folio_evicted,
	.folio_added = (void *)mglru_folio_added,
};
