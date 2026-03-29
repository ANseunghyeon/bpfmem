#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"
#include "cache_ext_lhd.bpf.h"
#include "unified_metadata.bpf.h"

char _license[] SEC("license") = "GPL";

#define INT64_MAX (9223372036854775807LL)
#define ENOENT 2

// MGLRU Constants
#define MAX_NR_TIERS 4
#define MIN_NR_GENS 2
#define MAX_NR_GENS 4
#define NR_HIST_GENS 1
#define MIN_LRU_BATCH 64

// Atomics
#define atomic_long_read(ptr) (*(volatile typeof(*(ptr)) *)(ptr))
#define atomic_long_zero(ptr) do { *(ptr) = 0; } while(0)
#define atomic_long_store(ptr, val) do { *(ptr) = (val); } while(0)

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))


// Policy Configuration Map
// Key: 0, Value: Current Policy ID
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} policy_config_map SEC(".maps");

static inline u32 get_current_policy(void) {
	u32 key = 0;
	u32 *policy = bpf_map_lookup_elem(&policy_config_map, &key);
	if (!policy) return POLICY_ID_FIFO;
	return *policy;
}

// Unified Lists: Shared across policies to save resources (limit ~4 lists)
// FIFO/MRU: uses lists[0]
// S3FIFO: uses lists[0] (small), lists[1] (main)
// MGLRU: uses lists[0..3] (generations)
static __u64 unified_lists[MAX_NR_GENS];

#define list_primary unified_lists[0]
#define list_secondary unified_lists[1]
#define mglru_lists unified_lists

static s64 s3fifo_small_size = 0;
static s64 s3fifo_main_size = 0;

// S3FIFO Cache Size (Set from userspace)
#define DEFAULT_CACHE_SIZE (((1ull << 20) * 200) / 4096)
const volatile size_t cache_size = DEFAULT_CACHE_SIZE;

// static __u64 mglru_lists[MAX_NR_GENS];

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

struct eviction_metadata {
	__u64 curr_gen;
	__u64 next_gen;
	__u64 iter_reached;
	__u64 tier_threshold;
	long stat_moved_pages;
	long stat_protected[MAX_NR_TIERS];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct eviction_metadata);
} mglru_percpu_array SEC(".maps");

static volatile bool unified_initialized = false;

static inline bool is_folio_relevant(struct folio *folio) {
	if (!folio || !folio->mapping || !folio->mapping->host)
		return false;
	return inode_in_watchlist(folio->mapping->host->i_ino);
}

#define DEFINE_LRUGEN_void                                                     \
	struct mglru_global_metadata *lrugen;                                  \
	int key__ = 0;                                                         \
	lrugen = bpf_map_lookup_elem(&mglru_global_metadata_map, &key__);      \
	if (!lrugen) return;

#define DEFINE_LRUGEN_int                                                      \
	struct mglru_global_metadata *lrugen;                                  \
	int key__ = 0;                                                         \
	lrugen = bpf_map_lookup_elem(&mglru_global_metadata_map, &key__);      \
	if (!lrugen) return 0;

#define DEFINE_MIN_SEQ(lrugen) unsigned long min_seq = READ_ONCE(lrugen->min_seq)
#define DEFINE_MAX_SEQ(lrugen) unsigned long max_seq = READ_ONCE(lrugen->max_seq)

inline void update_refaulted_stat(struct mglru_global_metadata *lrugen, int tier_idx, s64 delta) {
	tier_idx &= (MAX_NR_TIERS - 1);
	__sync_fetch_and_add(&lrugen->refaulted[tier_idx], delta);
}

inline void update_evicted_stat(struct mglru_global_metadata *lrugen, int tier_idx, s64 delta) {
	tier_idx &= (MAX_NR_TIERS - 1);
	__sync_fetch_and_add(&lrugen->evicted[tier_idx], delta);
}

inline void update_nr_pages_stat(struct mglru_global_metadata *lrugen, unsigned int gen_idx, s64 delta) {
	gen_idx &= (MAX_NR_GENS - 1);
	__sync_fetch_and_add(&lrugen->nr_pages[gen_idx], delta);
}

inline void update_tier_selected_stat(struct mglru_global_metadata *lrugen, int tier_idx, s64 delta) {
	tier_idx &= (MAX_NR_TIERS - 1);
	__sync_fetch_and_add(&lrugen->tier_selected[tier_idx], delta);
}

inline s64 read_nr_pages_stat(struct mglru_global_metadata *lrugen, unsigned int gen_idx) {
	if (gen_idx >= MAX_NR_GENS) return 0;
	return max(0, atomic_long_read(&lrugen->nr_pages[gen_idx]));
}

inline void update_protected_stat(struct mglru_global_metadata *lrugen, int tier_idx, s64 delta) {
	if (tier_idx > 0)
		__sync_fetch_and_add(&lrugen->protected[tier_idx - 1], delta);
}

// PID Controller Logic
struct ctrl_pos___x {
	unsigned long refaulted;
	unsigned long total;
	int gain;
};

static inline void read_ctrl_pos(struct mglru_global_metadata *lrugen, int tier, int gain, struct ctrl_pos___x *pos) {
	pos->refaulted = lrugen->avg_refaulted[tier] + __sync_fetch_and_add(&lrugen->refaulted[tier], 0);
	pos->total = lrugen->avg_total[tier] + __sync_fetch_and_add(&lrugen->evicted[tier], 0);
	if (tier) pos->total += lrugen->protected[tier - 1];
	pos->gain = gain;
}

static inline void reset_ctrl_pos(struct mglru_global_metadata *lrugen, bool carryover) {
	int tier;
	bool clear = carryover ? NR_HIST_GENS == 1 : NR_HIST_GENS > 1;
	if (!carryover && !clear) return;
	for (tier = 0; tier < MAX_NR_TIERS; tier++) {
		if (carryover) {
			unsigned long sum;
			sum = lrugen->avg_refaulted[tier] + atomic_long_read(&lrugen->refaulted[tier]);
			WRITE_ONCE(lrugen->avg_refaulted[tier], sum / 2);
			sum = lrugen->avg_total[tier] + atomic_long_read(&lrugen->evicted[tier]);
			if (tier) sum += lrugen->protected[tier - 1];
			WRITE_ONCE(lrugen->avg_total[tier], sum / 2);
		}
		if (clear) {
			atomic_long_zero(&lrugen->refaulted[tier]);
			atomic_long_zero(&lrugen->evicted[tier]);
			if (tier) WRITE_ONCE(lrugen->protected[tier - 1], 0);
		}
	}
}

static inline bool positive_ctrl_err(struct ctrl_pos___x *sp, struct ctrl_pos___x *pv) {
	return pv->refaulted < MIN_LRU_BATCH ||
	       pv->refaulted * (sp->total + MIN_LRU_BATCH) * sp->gain <= (sp->refaulted + 1) * pv->total * pv->gain;
}

static inline int get_tier_idx(struct mglru_global_metadata *lrugen) {
	int tier;
	struct ctrl_pos___x sp, pv;
	read_ctrl_pos(lrugen, 0, 1, &sp);
	for (tier = 1; tier < MAX_NR_TIERS; tier++) {
		read_ctrl_pos(lrugen, tier, 2, &pv);
		if (!positive_ctrl_err(&sp, &pv)) break;
	}
	return tier - 1;
}

static inline unsigned int lru_gen_from_seq(unsigned long seq) { return seq % MAX_NR_GENS; }
static inline bool folio_test_active(struct unified_folio_metadata *meta) { return meta && meta->data.mglru.freq >= 2; }
static inline int order_base_2(int n) {
	if (n <= 1) return 0;
	if (n <= 3) return 1;
	if (n <= 7) return 2;
	return 3;
}
static inline int lru_tier_from_refs(int refs) { return order_base_2(refs); }
static inline bool gen_within_limits(unsigned int gen) { return gen < MAX_NR_GENS; }
static inline int get_nr_gens(struct mglru_global_metadata *lrugen) { return lrugen->max_seq - lrugen->min_seq + 1; }

static inline bool gen_almost_empty(struct mglru_global_metadata *lrugen, int min_seq) {
	int oldest_gen = lru_gen_from_seq(min_seq);
	int nr_folios = read_nr_pages_stat(lrugen, oldest_gen);
	return nr_folios <= 4;
}

static inline bool lru_gen_add_folio(struct folio *folio, struct ghost_metadata *ghost) {
	if (folio_test_unevictable(folio)) return false;
	DEFINE_LRUGEN_int;
	DEFINE_MIN_SEQ(lrugen);
	DEFINE_MAX_SEQ(lrugen);
	
	unsigned long seq;
	struct unified_folio_metadata *meta = unified_get_metadata(folio);
	
	if (meta && folio_test_active(meta)) seq = max_seq;
	else if ((folio_test_reclaim(folio) && (folio_test_dirty(folio) || folio_test_writeback(folio)))) seq = max_seq - 1;
	else if (min_seq + MIN_NR_GENS >= max_seq) seq = min_seq;
	else seq = min_seq + 1;

	unsigned int gen = lru_gen_from_seq(seq);
	if (!gen_within_limits(gen)) return false;

	if (unified_create_metadata_with_freq(folio, POLICY_ID_MGLRU, gen, 1)) return false;
	
	meta = unified_get_metadata(folio);
	if (!meta) return false;
	
	meta->data.mglru.gen = gen;
	if (ghost) {
		meta->flags |= UNIFIED_FLAG_FROM_GHOST;
		if (ghost->access_count > 0) meta->access_count = ghost->access_count;
		update_refaulted_stat(lrugen, ghost->tier, 1);
		unified_stats_record_ghost_hit();
	} else {
		unified_stats_record_unique_page();
	}
	
	update_nr_pages_stat(lrugen, gen, folio_nr_pages(folio));
	if (bpf_cache_ext_list_add(mglru_lists[gen], folio)) {
		unified_delete_metadata(folio);
		return false;
	}
	return true;
}

static inline bool should_run_aging(struct mglru_global_metadata *lrugen, unsigned long max_seq) {
	DEFINE_MIN_SEQ(lrugen);
	if (min_seq + MIN_NR_GENS > max_seq) return true;
	
	unsigned long old = 0, young = 0, total = 0;
	int max_iter = min(MAX_NR_GENS, max_seq - min_seq);
	for (int i = 0; i < max_iter; i++) {
		unsigned long seq = min_seq + i;
		unsigned long size = max(read_nr_pages_stat(lrugen, lru_gen_from_seq(seq)), 0L);
		total += size;
		if (seq == max_seq) young += size;
		else if (seq + MIN_NR_GENS == max_seq) old += size;
	}
	if (min_seq + MIN_NR_GENS < max_seq) return false;
	if (young * MIN_NR_GENS > total) return true;
	if (old * (MIN_NR_GENS + 2) < total) return true;
	return false;
}

static inline bool try_to_inc_min_seq(struct mglru_global_metadata *lrugen) {
	DEFINE_MIN_SEQ(lrugen);
	if (!gen_almost_empty(lrugen, min_seq)) return false;
	WRITE_ONCE(lrugen->min_seq, lrugen->min_seq + 1);
	reset_ctrl_pos(lrugen, true);
	return true;
}

static inline bool try_to_inc_max_seq(struct mglru_global_metadata *lrugen) {
	if (get_nr_gens(lrugen) == MAX_NR_GENS) {
		if (!try_to_inc_min_seq(lrugen)) return false;
	}
	reset_ctrl_pos(lrugen, false);
	WRITE_ONCE(lrugen->max_seq, lrugen->max_seq + 1);
	return true;
}



// LHD Variables
static u64 lhd_next_reconfiguration = REQS_PER_RECONFIG;
static u32 lhd_num_reconfigurations = 0;
static u64 lhd_age_coarsening_shift = INITIAL_AGE_COARSENING_SHIFT;
static u64 lhd_ewma_num_objects = 0;
static u64 lhd_ewma_num_objects_mass = 0;
static u64 lhd_ewma_victim_hit_density = 0;
static u64 lhd_timestamp = 0;
static u64 lhd_overflows = 0;
static u64 lhd_num_objects = 0;

struct lhd_class {
	u64 total_hits;
	u64 total_evictions;
	u64 hits[MAX_AGE];
	u64 evictions[MAX_AGE];
	u64 hit_densities[MAX_AGE];
};

static struct lhd_class lhd_classes[NUM_CLASSES];

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} lhd_events SEC(".maps");

// LHD Helpers
static inline long lhd_ewma_decay(u64 val) { return (val * 9) / 10; }
static inline long lhd_rem_ewma_decay(u64 val) { return val / 10; }
static inline u32 lhd_hit_age_to_class(u64 hit_age) {
	u32 class = 0;
	if (hit_age == 0) return 0;
	while (hit_age < MAX_AGE && class < HIT_AGE_CLASSES - 1) {
		hit_age <<= 1;
		class++;
	}
	return class;
}
static inline u32 lhd_get_class_id(struct unified_folio_metadata *data) {
	u32 hit_age_id = lhd_hit_age_to_class(data->data.lhd.last_hit_age + data->data.lhd.last_last_hit_age);
	return data->data.lhd.app_class * HIT_AGE_CLASSES + hit_age_id;
}
static inline struct lhd_class *lhd_get_class(struct unified_folio_metadata *data) {
	u32 class_id = lhd_get_class_id(data);
	return &lhd_classes[class_id & NUM_CLASSES_MASK];
}
static inline u64 lhd_get_age(struct unified_folio_metadata *data) {
	u64 age = (lhd_timestamp - (data->insert_time_ns / 1000000)) >> lhd_age_coarsening_shift;
	if (age >= MAX_AGE) { lhd_overflows++; return MAX_AGE - 1; } 
	return age;
}
static inline u64 lhd_get_hit_density(struct unified_folio_metadata *data) {
	u64 age = lhd_get_age(data);
	if (age == MAX_AGE - 1) return 0;
	struct lhd_class *cls = lhd_get_class(data);
	if (!cls) return -1;
	return cls->hit_densities[age & MAX_AGE_MASK];
}
static inline void lhd_update_class(struct lhd_class *class) {
	int i;
	class->total_hits = 0;
	class->total_evictions = 0;
	bpf_for(i, 0, MAX_AGE) {
		class->hits[i] = lhd_ewma_decay(class->hits[i]);
		class->evictions[i] = lhd_ewma_decay(class->evictions[i]);
		class->total_hits += class->hits[i];
		class->total_evictions += class->evictions[i];
	}
}
static inline void lhd_stretch_distribution(s32 delta) {
	int i;
	bpf_for(i, 0, NUM_CLASSES) {
		struct lhd_class *cls = &lhd_classes[i];
		int init_age = MAX_AGE >> (-delta);
		u32 j;
		bpf_for(j, init_age, MAX_AGE - 1) {
			cls->hits[MAX_AGE - 1] += cls->hits[j];
			cls->evictions[MAX_AGE - 1] = cls->evictions[j];
		}
		bpf_for(j, 2, MAX_AGE + 1) {
			u32 index = MAX_AGE - j;
			cls->hits[index & MAX_AGE_MASK] = cls->hits[(j >> (-delta)) & MAX_AGE_MASK] / (1 << (-delta));
			cls->evictions[index & MAX_AGE_MASK] = cls->evictions[(j >> (-delta)) & MAX_AGE_MASK] / (1 << (-delta));
		}
	}
}
static inline void lhd_compress_distribution(s32 delta) {
	int i;
	bpf_for(i, 0, NUM_CLASSES) {
		struct lhd_class *cls = &lhd_classes[i];
		u32 j;
		bpf_for(j, 0, MAX_AGE >> delta) {
			cls->hits[j & MAX_AGE_MASK] = cls->hits[(j << delta) & MAX_AGE_MASK];
			cls->evictions[j & MAX_AGE_MASK] = cls->evictions[(j << delta) & MAX_AGE_MASK];
			int k;
			bpf_for(k, 1, (1 << delta)) {
				cls->hits[j & MAX_AGE_MASK] += cls->hits[((j << delta) + k) & MAX_AGE_MASK];
				cls->evictions[j & MAX_AGE_MASK] += cls->evictions[((j << delta) + k) & MAX_AGE_MASK];
			}
		}
		bpf_for(j, MAX_AGE >> delta, MAX_AGE - 1) {
			cls->hits[j & MAX_AGE_MASK] = 0;
			cls->evictions[j & MAX_AGE_MASK] = 0;
		}
	}
}
static inline void lhd_adapt_age_coarsening(void) {
	lhd_ewma_num_objects = lhd_ewma_decay(lhd_ewma_num_objects);
	lhd_ewma_num_objects_mass = lhd_ewma_decay(lhd_ewma_num_objects_mass);
	lhd_ewma_num_objects += lhd_num_objects * NUM_OBJECTS_SCALING_FACTOR;
	lhd_ewma_num_objects_mass += 1;
	u64 num_objects_coarsening = lhd_ewma_num_objects / lhd_ewma_num_objects_mass;
	u64 optimal_age_coarsening = 1 * num_objects_coarsening * AGE_COARSENING_ERROR_TOLERANCE / MAX_AGE;
	if (lhd_num_reconfigurations == 5 || lhd_num_reconfigurations == 25) {
		u32 optimal_age_coarsening_log2 = 1;
		while ((1 << optimal_age_coarsening_log2) * NUM_OBJECTS_SCALING_FACTOR < optimal_age_coarsening)
			optimal_age_coarsening_log2++;
		s32 delta = optimal_age_coarsening_log2 - lhd_age_coarsening_shift;
		lhd_age_coarsening_shift = optimal_age_coarsening_log2;
		lhd_ewma_num_objects *= 8;
		lhd_ewma_num_objects_mass *= 8;
		if (delta < 0) lhd_stretch_distribution(delta);
		else if (delta > 0) lhd_compress_distribution(delta);
	}
}
static inline void lhd_model_hit_density(void) {
	int i;
	bpf_for(i, 0, NUM_CLASSES) {
		struct lhd_class *cls = &lhd_classes[i];
		u64 total_hits = cls->hits[MAX_AGE - 1];
		u64 total_events = total_hits + cls->evictions[MAX_AGE - 1];
		u64 lifetime_unconditoned = total_events;
		int j;
		bpf_for(j, 2, MAX_AGE + 1) {
			u32 index = MAX_AGE - j;
			total_hits += cls->hits[index & MAX_AGE_MASK];
			total_events += cls->evictions[index & MAX_AGE_MASK];
			lifetime_unconditoned += total_events;
			if (total_events > TOTAL_EVENTS_THRESH)
				cls->hit_densities[index & MAX_AGE_MASK] = total_hits * HIT_DENSITY_SCALING_FACTOR / lifetime_unconditoned;
			else
				cls->hit_densities[index & MAX_AGE_MASK] = 0;
		}
	}
}

SEC("syscall")
int reconfigure(void) {
	int i;
	bpf_for(i, 0, NUM_CLASSES) {
		lhd_update_class(&lhd_classes[i]);
	}
	lhd_adapt_age_coarsening();
	lhd_model_hit_density();
	lhd_overflows = 0;
	return 0;
}

static s64 bpf_lhd_score_fn(int idx, struct cache_ext_list_node *a) {
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
		return INT64_MAX;
	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
		return INT64_MAX;
	struct unified_folio_metadata *data = unified_get_metadata(a->folio);
	if (!data) return INT64_MAX;
	return lhd_get_hit_density(data);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(unified_init, struct mem_cgroup *memcg)
{
	bpf_printk("cache_ext: Unified init starting\n");

	// Create Lists (Shared)
	// We use 4 lists total.
	// 0: FIFO/MRU/S3FIFO-Small/MGLRU-Gen0
	// 1: S3FIFO-Main/MGLRU-Gen1
	// 2: MGLRU-Gen2
	// 3: MGLRU-Gen3
	for (int i = 0; i < MAX_NR_GENS; i++) {
		unified_lists[i] = bpf_cache_ext_ds_registry_new_list(memcg);
		if (!unified_lists[i]) {
			bpf_printk("cache_ext: Failed to create list %d\n", i);
			return -1;
		}
	}

	int key = 0;
	struct mglru_global_metadata *lrugen_chk = bpf_map_lookup_elem(&mglru_global_metadata_map, &key);
	if (!lrugen_chk) {
		bpf_printk("cache_ext: Failed to lookup mglru map\n");
		return -1;
	}

	WRITE_ONCE(lrugen_chk->max_seq, MIN_NR_GENS + 1);

	bpf_printk("cache_ext: Lists created\n");

	
	// Initialize LHD hit densities
	uint32_t lhd_i;
	bpf_for(lhd_i, 0, NUM_CLASSES) {
		uint32_t lhd_j;
		struct lhd_class *cls = &lhd_classes[lhd_i];
		bpf_for(lhd_j, 0, MAX_AGE) {
			cls->hit_densities[lhd_j] = 1 * HIT_DENSITY_SCALING_FACTOR * (lhd_i + 1) / (lhd_j + 1);
		}
	}

	unified_initialized = true;
	return 0;
}


void BPF_STRUCT_OPS(unified_folio_added, struct folio *folio)
{
	if (!unified_initialized || !is_folio_relevant(folio)) return;
	u32 policy = get_current_policy();

	if (policy == POLICY_ID_MGLRU) {
		struct ghost_metadata ghost_val;
		struct ghost_metadata *ghost_ptr = NULL;
		if (unified_pop_ghost(folio, &ghost_val)) ghost_ptr = &ghost_val;
		lru_gen_add_folio(folio, ghost_ptr);
		return;
	}

	
	if (policy == POLICY_ID_LHD) {
		struct ghost_metadata ghost;
		bool from_ghost = unified_pop_ghost(folio, &ghost);
		
		if (bpf_cache_ext_list_add_tail(list_primary, folio)) return;
		
		if (unified_create_metadata(folio, policy, 0)) {
			bpf_cache_ext_list_del(folio);
			return;
		}
		
		struct unified_folio_metadata *meta = unified_get_metadata(folio);
		if (meta) {
			meta->data.lhd.last_hit_age = 0;
			meta->data.lhd.last_last_hit_age = MAX_AGE;
			meta->data.lhd.app_class = DEFAULT_APP_ID % APP_CLASSES;
			
			if (from_ghost) {
				meta->flags |= UNIFIED_FLAG_FROM_GHOST;
				unified_stats_record_ghost_hit();
			} else {
				unified_stats_record_unique_page();
			}
		}
		
		__sync_fetch_and_add(&lhd_timestamp, 1);
		__sync_fetch_and_add(&lhd_num_objects, 1);
		
		if (__sync_sub_and_fetch(&lhd_next_reconfiguration, 1) == 0) {
			lhd_next_reconfiguration = REQS_PER_RECONFIG;
			lhd_num_reconfigurations++;
			bpf_ringbuf_output(&lhd_events, &lhd_num_reconfigurations, sizeof(lhd_num_reconfigurations), 0);
		}
		return;
	}

	u64 target_list = list_primary;

	u16 list_idx = 0;
	u32 flags = 0;
	
	if (policy == POLICY_ID_S3FIFO) {
		struct ghost_metadata ghost;
		if (unified_pop_ghost(folio, &ghost)) {
			target_list = list_secondary;
			list_idx = 1;
			flags = UNIFIED_FLAG_IN_MAIN | UNIFIED_FLAG_FROM_GHOST;
			__sync_fetch_and_add(&s3fifo_main_size, 1);
			unified_stats_record_ghost_hit();
		} else {
			target_list = list_primary;
			list_idx = 0;
			__sync_fetch_and_add(&s3fifo_small_size, 1);
			unified_stats_record_unique_page();
		}
	} else {
		unified_check_and_delete_ghost(folio);
		unified_stats_record_unique_page();
	}

	if (bpf_cache_ext_list_add_tail(target_list, folio)) return;

	if (policy == POLICY_ID_S3FIFO) {
		if (unified_create_metadata_with_freq(folio, policy, list_idx, 0)) {
			bpf_cache_ext_list_del(folio);
			return;
		}
	} else {
		if (unified_create_metadata(folio, policy, list_idx)) {
			bpf_cache_ext_list_del(folio);
			return;
		}
	}

	struct unified_folio_metadata *meta = unified_get_metadata(folio);
	if (meta) meta->flags = flags;
}


void BPF_STRUCT_OPS(unified_folio_accessed, struct folio *folio)
{
	if (!unified_initialized || !is_folio_relevant(folio)) return;
	u32 policy = get_current_policy();
	
	bool is_reaccess = unified_record_access(folio);
	unified_stats_record_access(is_reaccess, unified_is_sequential(folio));

	struct unified_folio_metadata *meta = unified_get_metadata(folio);
	if (!meta) return;

	switch (policy) {
	case POLICY_ID_MRU:
		bpf_cache_ext_list_move(list_primary, folio, false);
		break;
	case POLICY_ID_S3FIFO:
		__sync_fetch_and_add(&meta->data.mglru.freq, 1);
		if (meta->data.mglru.freq > 3) meta->data.mglru.freq = 3;
		break;
	case POLICY_ID_MGLRU:
		__sync_fetch_and_add(&meta->data.mglru.freq, 1);
		break;
	
	case POLICY_ID_LHD: {
		u64 age = lhd_get_age(meta);
		struct lhd_class *cls = lhd_get_class(meta);
		if (cls) {
			meta->data.lhd.last_last_hit_age = meta->data.lhd.last_hit_age;
			meta->data.lhd.last_hit_age = age;
			meta->last_access_ns = bpf_ktime_get_ns();
			
			u64 *hits = cls->hits + age;
			__sync_fetch_and_add(hits, 1 * HIT_SCALING_FACTOR);
			__sync_fetch_and_add(&lhd_timestamp, 1);
			
			if (__sync_sub_and_fetch(&lhd_next_reconfiguration, 1) == 0) {
				lhd_next_reconfiguration = REQS_PER_RECONFIG;
				lhd_num_reconfigurations++;
				bpf_ringbuf_output(&lhd_events, &lhd_num_reconfigurations, sizeof(lhd_num_reconfigurations), 0);
			}
		}
		break;
	}
	default: break;

	}
}


void BPF_STRUCT_OPS(unified_folio_evicted, struct folio *folio)
{
	if (!unified_initialized) return;
	bpf_cache_ext_list_del(folio);

	struct unified_folio_metadata *meta = unified_get_metadata(folio);
	if (!meta) return;

	u32 policy = get_current_policy();
	u32 meta_policy = meta->policy_id;
	
	if (policy == POLICY_ID_S3FIFO || meta_policy == POLICY_ID_S3FIFO) {
		if (meta->flags & UNIFIED_FLAG_IN_MAIN) __sync_fetch_and_sub(&s3fifo_main_size, 1);
		else __sync_fetch_and_sub(&s3fifo_small_size, 1);
	}
	
	
	if (policy == POLICY_ID_LHD || meta_policy == POLICY_ID_LHD) {
		u64 age = lhd_get_age(meta);
		struct lhd_class *cls = lhd_get_class(meta);
		if (cls) {
			u64 *evictions = cls->evictions + age;
			__sync_fetch_and_add(evictions, 1 * HIT_SCALING_FACTOR);
			__sync_fetch_and_sub(&lhd_num_objects, 1);
			
			u64 hit_density = cls->hit_densities[age];
			lhd_ewma_victim_hit_density = lhd_ewma_decay(lhd_ewma_victim_hit_density) + lhd_rem_ewma_decay(hit_density);
		}
		u8 tier = unified_access_count_to_tier(meta->access_count);
		unified_add_ghost(folio, POLICY_ID_LHD, tier);
	} else if (policy == POLICY_ID_MGLRU || meta_policy == POLICY_ID_MGLRU) {

		DEFINE_LRUGEN_void;
		int tier = lru_tier_from_refs(atomic_long_read(&meta->data.mglru.freq));
		update_evicted_stat(lrugen, tier, 1);
		update_nr_pages_stat(lrugen, meta->data.mglru.gen, -folio_nr_pages(folio));
		unified_add_ghost(folio, POLICY_ID_MGLRU, tier);
	} else {
		u8 tier = (meta->flags & UNIFIED_FLAG_IN_MAIN) ? 1 : 0;
		unified_add_ghost(folio, policy, tier);
	}
	
	unified_stats_record_eviction();
	unified_delete_metadata(folio);
}

static int simple_evict_cb(int idx, struct cache_ext_list_node *a)
{
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio)) return CACHE_EXT_CONTINUE_ITER;
	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio)) return CACHE_EXT_CONTINUE_ITER;
	return CACHE_EXT_EVICT_NODE;
}

static int s3fifo_score_small_fn(int idx, struct cache_ext_list_node *a)
{
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio)) return CACHE_EXT_CONTINUE_ITER;
	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio)) return CACHE_EXT_CONTINUE_ITER;
	struct unified_folio_metadata *data = unified_get_metadata(a->folio);
	if (!data) return CACHE_EXT_CONTINUE_ITER;
	if (data->data.mglru.freq > 1) {
		data->flags |= UNIFIED_FLAG_IN_MAIN;
		data->list_idx = 1;
		return CACHE_EXT_CONTINUE_ITER;
	}
	return CACHE_EXT_EVICT_NODE;
}

static int s3fifo_score_main_iter_fn(int idx, struct cache_ext_list_node *a, int threshold)
{
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio)) return CACHE_EXT_CONTINUE_ITER;
	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio)) return CACHE_EXT_CONTINUE_ITER;
	struct unified_folio_metadata *data = unified_get_metadata(a->folio);
	if (!data) return CACHE_EXT_CONTINUE_ITER;
	__sync_fetch_and_sub(&data->data.mglru.freq, 1);
	if (data->data.mglru.freq < threshold) return CACHE_EXT_EVICT_NODE;
	return CACHE_EXT_CONTINUE_ITER;
}

#define S3FIFO_MAIN_ITER(id) static int s3fifo_main_iter_##id(int idx, struct cache_ext_list_node *a) { return s3fifo_score_main_iter_fn(idx, a, id); }
S3FIFO_MAIN_ITER(0) S3FIFO_MAIN_ITER(1) S3FIFO_MAIN_ITER(2) S3FIFO_MAIN_ITER(3)

// MGLRU Eviction
static int mglru_iter_fn(int idx, struct cache_ext_list_node *a)
{
	u32 key = 0;
	struct eviction_metadata *ev_meta = bpf_map_lookup_elem(&mglru_percpu_array, &key);
	if (!ev_meta) return CACHE_EXT_EVICT_NODE;
	
	ev_meta->iter_reached = idx;
	struct unified_folio_metadata *meta = unified_get_metadata(a->folio);
	if (!meta) return CACHE_EXT_EVICT_NODE;
	
	int tier = lru_tier_from_refs(atomic_long_read(&meta->data.mglru.freq));
	if (tier > ev_meta->tier_threshold) {
		if (tier < MAX_NR_TIERS) __sync_fetch_and_add(&ev_meta->stat_protected[tier], folio_nr_pages(a->folio));
		int num_pages = folio_nr_pages(a->folio);
		__sync_fetch_and_add(&ev_meta->stat_moved_pages, num_pages);
		atomic_long_store(&meta->data.mglru.gen, ev_meta->next_gen);
		return CACHE_EXT_CONTINUE_ITER;
	}
	if (folio_test_locked(a->folio) || folio_test_writeback(a->folio) || folio_test_dirty(a->folio)) {
		int num_pages = folio_nr_pages(a->folio);
		__sync_fetch_and_add(&ev_meta->stat_moved_pages, num_pages);
		atomic_long_store(&meta->data.mglru.gen, ev_meta->next_gen);
		return CACHE_EXT_CONTINUE_ITER;
	}
	return CACHE_EXT_EVICT_NODE;
}

void BPF_STRUCT_OPS(unified_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx, struct mem_cgroup *memcg)
{
	if (!unified_initialized) return;
	u32 policy = get_current_policy();

	if (policy == POLICY_ID_LHD) {
		struct sampling_options opts = {
			.sample_size = 16,
		};
		bpf_cache_ext_list_sample(memcg, list_primary, (void*)bpf_lhd_score_fn, &opts, eviction_ctx);
		
		if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
			bpf_cache_ext_list_iterate(memcg, list_secondary, simple_evict_cb, eviction_ctx);
		}
		if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
			bpf_cache_ext_list_iterate(memcg, mglru_lists[2], simple_evict_cb, eviction_ctx);
		}
		if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
			bpf_cache_ext_list_iterate(memcg, mglru_lists[3], simple_evict_cb, eviction_ctx);
		}
	} else if (policy == POLICY_ID_S3FIFO) {
		bool evict_small = (s3fifo_small_size >= cache_size / 10 || s3fifo_main_size <= 2 * s3fifo_small_size);
		if (evict_small) {
			struct cache_ext_iterate_opts opts = { .continue_list = list_secondary, .continue_mode = CACHE_EXT_ITERATE_TAIL, .evict_list = CACHE_EXT_ITERATE_SELF, .evict_mode = CACHE_EXT_ITERATE_TAIL };
			bpf_cache_ext_list_iterate_extended(memcg, list_primary, s3fifo_score_small_fn, &opts, eviction_ctx);
			if (opts.nr_folios_continue > 0) {
				__sync_fetch_and_sub(&s3fifo_small_size, opts.nr_folios_continue);
				__sync_fetch_and_add(&s3fifo_main_size, opts.nr_folios_continue);
			}
		} else {
			struct cache_ext_iterate_opts opts = { .continue_list = CACHE_EXT_ITERATE_SELF, .continue_mode = CACHE_EXT_ITERATE_TAIL, .evict_list = CACHE_EXT_ITERATE_SELF, .evict_mode = CACHE_EXT_ITERATE_TAIL };
			if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) bpf_cache_ext_list_iterate_extended(memcg, list_secondary, s3fifo_main_iter_0, &opts, eviction_ctx);
			if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) bpf_cache_ext_list_iterate_extended(memcg, list_secondary, s3fifo_main_iter_1, &opts, eviction_ctx);
			if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) bpf_cache_ext_list_iterate_extended(memcg, list_secondary, s3fifo_main_iter_2, &opts, eviction_ctx);
			if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) bpf_cache_ext_list_iterate_extended(memcg, list_secondary, s3fifo_main_iter_3, &opts, eviction_ctx);
		}
		
		// Fallback: If S3FIFO logic didn't evict enough, try other lists (cleanup from MGLRU switch)
		if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
			bpf_cache_ext_list_iterate(memcg, mglru_lists[2], simple_evict_cb, eviction_ctx);
		}
		if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
			bpf_cache_ext_list_iterate(memcg, mglru_lists[3], simple_evict_cb, eviction_ctx);
		}
	} else if (policy == POLICY_ID_MGLRU) {
		DEFINE_LRUGEN_void;
		bpf_spin_lock(&lrugen->lock);
		DEFINE_MIN_SEQ(lrugen);
		DEFINE_MAX_SEQ(lrugen);
		if (should_run_aging(lrugen, max_seq)) try_to_inc_max_seq(lrugen);
		if (max_seq - min_seq > MIN_NR_GENS) try_to_inc_min_seq(lrugen);
		min_seq = READ_ONCE(lrugen->min_seq);
		int oldest_gen = lru_gen_from_seq(min_seq);
		volatile unsigned int next_gen = (oldest_gen + 1) % MAX_NR_GENS;
		bpf_spin_unlock(&lrugen->lock);

		int tier_threshold = get_tier_idx(lrugen);
		update_tier_selected_stat(lrugen, tier_threshold, 1);
		
		struct eviction_metadata ev_meta = { .curr_gen = oldest_gen, .next_gen = next_gen, .tier_threshold = tier_threshold, .stat_moved_pages = 0 };
		__builtin_memset(ev_meta.stat_protected, 0, sizeof(ev_meta.stat_protected));
		
		u32 key = 0;
		bpf_map_update_elem(&mglru_percpu_array, &key, &ev_meta, BPF_ANY);

		struct cache_ext_iterate_opts opts = { .continue_list = mglru_lists[next_gen], .continue_mode = CACHE_EXT_ITERATE_TAIL, .evict_list = CACHE_EXT_ITERATE_SELF, .evict_mode = CACHE_EXT_ITERATE_TAIL };
		bpf_cache_ext_list_iterate_extended(memcg, mglru_lists[oldest_gen], mglru_iter_fn, &opts, eviction_ctx);
		
		// Flush stats
		struct eviction_metadata *ev_meta_ptr = bpf_map_lookup_elem(&mglru_percpu_array, &key);
		if (ev_meta_ptr) {
			if (ev_meta_ptr->stat_moved_pages > 0) {
				update_nr_pages_stat(lrugen, oldest_gen, -ev_meta_ptr->stat_moved_pages);
				update_nr_pages_stat(lrugen, next_gen, ev_meta_ptr->stat_moved_pages);
			}
			for (int i = 1; i < MAX_NR_TIERS; i++) {
				if (ev_meta_ptr->stat_protected[i] > 0)
					update_protected_stat(lrugen, i, ev_meta_ptr->stat_protected[i]);
			}
		}
		
		if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
			// Try next gen
			min_seq = READ_ONCE(lrugen->min_seq); // re-read
			oldest_gen = lru_gen_from_seq(min_seq);
			next_gen = (oldest_gen + 1) % MAX_NR_GENS;
			
			// Reset stats for next pass
			ev_meta.curr_gen = oldest_gen;
			ev_meta.next_gen = next_gen;
			ev_meta.stat_moved_pages = 0;
			__builtin_memset(ev_meta.stat_protected, 0, sizeof(ev_meta.stat_protected));
			bpf_map_update_elem(&mglru_percpu_array, &key, &ev_meta, BPF_ANY);
			
			struct cache_ext_iterate_opts opts2 = { .continue_list = mglru_lists[next_gen], .continue_mode = CACHE_EXT_ITERATE_TAIL, .evict_list = CACHE_EXT_ITERATE_SELF, .evict_mode = CACHE_EXT_ITERATE_TAIL };
			bpf_cache_ext_list_iterate_extended(memcg, mglru_lists[oldest_gen], mglru_iter_fn, &opts2, eviction_ctx);
			
			// Flush stats again
			ev_meta_ptr = bpf_map_lookup_elem(&mglru_percpu_array, &key);
			if (ev_meta_ptr) {
				if (ev_meta_ptr->stat_moved_pages > 0) {
					update_nr_pages_stat(lrugen, oldest_gen, -ev_meta_ptr->stat_moved_pages);
					update_nr_pages_stat(lrugen, next_gen, ev_meta_ptr->stat_moved_pages);
				}
				for (int i = 1; i < MAX_NR_TIERS; i++) {
					if (ev_meta_ptr->stat_protected[i] > 0)
						update_protected_stat(lrugen, i, ev_meta_ptr->stat_protected[i]);
				}
			}
		}
	} else {
		// FIFO / MRU
		// Iterate ALL lists to ensure we don't leak pages when switching from MGLRU
		bpf_cache_ext_list_iterate(memcg, list_primary, simple_evict_cb, eviction_ctx);
		if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
			bpf_cache_ext_list_iterate(memcg, list_secondary, simple_evict_cb, eviction_ctx);
		}
		if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
			bpf_cache_ext_list_iterate(memcg, mglru_lists[2], simple_evict_cb, eviction_ctx);
		}
		if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
			bpf_cache_ext_list_iterate(memcg, mglru_lists[3], simple_evict_cb, eviction_ctx);
		}
	}
}

SEC(".struct_ops.link")
struct cache_ext_ops unified_ops = {
	.init = (void *)unified_init,
	.evict_folios = (void *)unified_evict_folios,
	.folio_accessed = (void *)unified_folio_accessed,
	.folio_evicted = (void *)unified_folio_evicted,
	.folio_added = (void *)unified_folio_added,
};
