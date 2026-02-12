#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"
#include "cache_ext_lhd.bpf.h"
#include "unified_metadata.bpf.h"

char _license[] SEC("license") = "GPL";

static u64 next_reconfiguration = REQS_PER_RECONFIG;
static u32 num_reconfigurations = 0;

static u64 age_coarsening_shift = INITIAL_AGE_COARSENING_SHIFT;
static u64 ewma_num_objects = 0;
static u64 ewma_num_objects_mass = 0;

static u64 ewma_victim_hit_density = 0;

// Current number of requests
static u64 timestamp = 0;

// For debugging purposes
static u64 overflows = 0;

static u64 lhd_list;
static volatile bool lhd_initialized = false;

static u64 num_objects = 0;

#define INT64_MAX  (9223372036854775807LL)

struct lhd_class {
	u64 total_hits;
	u64 total_evictions;

	u64 hits[MAX_AGE];
	u64 evictions[MAX_AGE];
	u64 hit_densities[MAX_AGE];
};

static struct lhd_class classes[NUM_CLASSES];

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events SEC(".maps");

static inline long ewma_decay(u64 val) {
	return (val * 9) / 10;
}

static inline long rem_ewma_decay(u64 val) {
	return val / 10;
}

static inline bool is_folio_relevant(struct folio *folio) {
	if (!folio || !folio->mapping || !folio->mapping->host)
		return false;

	return inode_in_watchlist(folio->mapping->host->i_ino);
}

static inline u32 hit_age_to_class(u64 hit_age) {
	u32 class = 0;

	if (hit_age == 0)
		return 0;

	// Approximates log(MAX_AGE - hit_age)
	while (hit_age < MAX_AGE && class < HIT_AGE_CLASSES - 1) {
		hit_age <<= 1;
		class++;
	}

	return class;
}

static inline u32 get_class_id(struct unified_folio_metadata *data) {
	u32 hit_age_id = hit_age_to_class(data->data.lhd.last_hit_age + data->data.lhd.last_last_hit_age);
	return data->data.lhd.app_class * HIT_AGE_CLASSES + hit_age_id;
}

static inline struct lhd_class *get_class(struct unified_folio_metadata *data) {
	u32 class_id = get_class_id(data);
	return &classes[class_id & NUM_CLASSES_MASK];
}

static inline u64 get_age(struct unified_folio_metadata *data) {
	u64 age = (timestamp - (data->insert_time_ns / 1000000)) >> age_coarsening_shift;

	if (age >= MAX_AGE) {
		overflows++;
		return MAX_AGE - 1;
	} 

	return age;
}

static inline u64 get_hit_density(struct unified_folio_metadata *data) {
	u64 age = get_age(data);
	if (age == MAX_AGE - 1)
		return 0;

	struct lhd_class *cls = get_class(data);
	if (!cls)
		return -1;

	return cls->hit_densities[age & MAX_AGE_MASK];
}

static inline void update_class(struct lhd_class *class) {
	int i;

	class->total_hits = 0;
	class->total_evictions = 0;

	bpf_for(i, 0, MAX_AGE) {
		class->hits[i] = ewma_decay(class->hits[i]);
		class->evictions[i] = ewma_decay(class->evictions[i]);

		class->total_hits += class->hits[i];
		class->total_evictions += class->evictions[i];
	}
}

static inline void stretch_distribution(s32 delta) {
	int i;
	bpf_for(i, 0, NUM_CLASSES) {
		struct lhd_class *cls = &classes[i];
		int init_age = MAX_AGE >> (-delta);
		u32 j;

		bpf_for(j, init_age, MAX_AGE - 1) {
			cls->hits[MAX_AGE - 1] += cls->hits[j];
			cls->evictions[MAX_AGE - 1] = cls->evictions[j];
		}
		bpf_for(j, 2, MAX_AGE + 1) { // MAX_AGE -2 -> 0
			u32 index = MAX_AGE - j;
			cls->hits[index & MAX_AGE_MASK] =
				cls->hits[(j >> (-delta)) & MAX_AGE_MASK] /
				(1 << (-delta));
			cls->evictions[index & MAX_AGE_MASK] =
				cls->evictions[(j >> (-delta)) & MAX_AGE_MASK] /
				(1 << (-delta));
		}
	}
}

static inline void compress_distribution(s32 delta) {
	int i;
	bpf_for(i, 0, NUM_CLASSES) {
		struct lhd_class *cls = &classes[i];
		u32 j;

		bpf_for(j, 0, MAX_AGE >> delta) {
			cls->hits[j & MAX_AGE_MASK] =
				cls->hits[(j << delta) & MAX_AGE_MASK];
			cls->evictions[j & MAX_AGE_MASK] =
				cls->evictions[(j << delta) & MAX_AGE_MASK];
			int k;
			bpf_for(k, 1, (1 << delta)) {
				cls->hits[j & MAX_AGE_MASK] +=
					cls->hits[((j << delta) + k) &
						  MAX_AGE_MASK];
				cls->evictions[j & MAX_AGE_MASK] +=
					cls->evictions[((j << delta) + k) &
						       MAX_AGE_MASK];
			}
		}

		bpf_for(j, MAX_AGE >> delta, MAX_AGE - 1) {
			cls->hits[j & MAX_AGE_MASK] = 0;
			cls->evictions[j & MAX_AGE_MASK] = 0;
		}
	}
}

static inline void adapt_age_coarsening(void) {
	ewma_num_objects = ewma_decay(ewma_num_objects);
	ewma_num_objects_mass = ewma_decay(ewma_num_objects_mass);

	ewma_num_objects += num_objects * NUM_OBJECTS_SCALING_FACTOR;
	ewma_num_objects_mass += 1;

	u64 num_objects_coarsening = ewma_num_objects / ewma_num_objects_mass;

	u64 optimal_age_coarsening =
		1 * num_objects_coarsening * AGE_COARSENING_ERROR_TOLERANCE / MAX_AGE;

	if (num_reconfigurations == 5 || num_reconfigurations == 25) {
		u32 optimal_age_coarsening_log2 = 1;

		while ((1 << optimal_age_coarsening_log2) * NUM_OBJECTS_SCALING_FACTOR <
		       optimal_age_coarsening)
			optimal_age_coarsening_log2++;

		s32 delta = optimal_age_coarsening_log2 - age_coarsening_shift;
		age_coarsening_shift = optimal_age_coarsening_log2;

		ewma_num_objects *= 8;
		ewma_num_objects_mass *= 8;

		if (delta < 0)
			stretch_distribution(delta);
		else if (delta > 0)
			compress_distribution(delta);
	}
}

static inline void model_hit_density(void) {
	int i;

	bpf_for(i, 0, NUM_CLASSES) {
		struct lhd_class *cls = &classes[i];
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
				cls->hit_densities[index & MAX_AGE_MASK] =
					total_hits * HIT_DENSITY_SCALING_FACTOR /
					lifetime_unconditoned;
			else
				cls->hit_densities[index & MAX_AGE_MASK] = 0;
		}
	}
}

SEC("syscall")
int reconfigure(void) {
	int i;

	bpf_for(i, 0, NUM_CLASSES) {
		update_class(&classes[i]);
	}

	adapt_age_coarsening();

	model_hit_density();

	overflows = 0;

	return 0;
}

/*
 * Callback for inherit_iterate: convert inherited pages to LHD metadata
 */
static int lhd_inherit_callback(int idx, struct cache_ext_list_node *node)
{
	struct unified_folio_metadata *meta = unified_get_metadata(node->folio);
	
	if (!meta) {
		// Create new metadata for inherited page
		if (unified_create_metadata(node->folio, POLICY_ID_LHD, 0)) {
			return 2;  // Skip if we can't create metadata
		}
		meta = unified_get_metadata(node->folio);
		if (!meta)
			return 2;
	}
	
	// Convert to LHD metadata
	meta->policy_id = POLICY_ID_LHD;
	meta->flags |= UNIFIED_FLAG_INHERITED;
	
	// Initialize LHD-specific fields based on access history
	// Use access_count to estimate hit age class
	if (meta->access_count >= 3) {
		meta->data.lhd.last_hit_age = 0;  // Frequently accessed = low hit age
		meta->data.lhd.last_last_hit_age = 0;
	} else if (meta->access_count >= 2) {
		meta->data.lhd.last_hit_age = MAX_AGE / 4;
		meta->data.lhd.last_last_hit_age = MAX_AGE / 2;
	} else {
		meta->data.lhd.last_hit_age = MAX_AGE / 2;
		meta->data.lhd.last_last_hit_age = MAX_AGE;
	}
	meta->data.lhd.app_class = DEFAULT_APP_ID % APP_CLASSES;
	
	__sync_fetch_and_add(&num_objects, 1);
	return 0;  // Move to target list
}

s32 BPF_STRUCT_OPS_SLEEPABLE(lhd_init, struct mem_cgroup *memcg) {
	uint32_t i;

	bpf_printk("cache_ext: LHD init starting, memcg=%p\n", memcg);

	lhd_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (lhd_list == 0) {
		bpf_printk("cache_ext: init: Failed to create lhd_list\n");
		return -1;
	}
	bpf_printk("cache_ext: Created lhd_list: %llu\n", lhd_list);

	/*
	 * BPF global variables are zero-initialized, so we only need to
	 * initialize the hit densities.
	 */
	bpf_for(i, 0, NUM_CLASSES) {
		uint32_t j;

		// Initialize hit densities to GDSF
		struct lhd_class *cls = &classes[i];
		bpf_for(j, 0, MAX_AGE) {
			cls->hit_densities[j] = 1 * HIT_DENSITY_SCALING_FACTOR * (i + 1) / (j + 1);
		}
	}

	// Check for inherited pages
	bool has_pages = bpf_cache_ext_inherit_has_pages(memcg);
	u64 inherit_count = bpf_cache_ext_inherit_get_count(memcg);
	bpf_printk("cache_ext: LHD inherit check: has_pages=%d, count=%llu\n",
		   has_pages, inherit_count);

	if (has_pages && inherit_count > 0) {
		bpf_printk("cache_ext: LHD inheriting %llu pages\n", inherit_count);
		
		int processed = bpf_cache_ext_inherit_iterate(
			memcg,
			lhd_list,
			lhd_inherit_callback,
			0
		);
		
		bpf_printk("cache_ext: LHD actually inherited %d pages\n", processed);
	}

	lhd_initialized = true;
	bpf_printk("cache_ext: LHD init complete\n");

	return 0;
}

static s64 bpf_lhd_score_fn(struct cache_ext_list_node *a) {
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
		return INT64_MAX;

	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
		return INT64_MAX;

	struct unified_folio_metadata *data = unified_get_metadata(a->folio);
	if (!data) {
		bpf_printk("cache_ext: score_fn: Failed to get metadata\n");
		return INT64_MAX;
	}

	return get_hit_density(data);
}

void BPF_STRUCT_OPS(lhd_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
	       struct mem_cgroup *memcg)
{
	if (!lhd_initialized)
		return;

	struct sampling_options opts = {
		.sample_size = 16,
	};

	if (bpf_cache_ext_list_sample(memcg, lhd_list, bpf_lhd_score_fn, &opts, eviction_ctx)) {
		bpf_printk("cache_ext: evict: Failed to sample\n");
		return;
	}
}

void BPF_STRUCT_OPS(lhd_folio_accessed, struct folio *folio) {
	if (!lhd_initialized)
		return;

	if (!is_folio_relevant(folio))
		return;

	struct unified_folio_metadata *data = unified_get_metadata(folio);
	if (!data) {
		bpf_printk("cache_ext: accessed: Failed to get metadata\n");
		return;
	}

	// Record access for reaccess tracking
	bool is_reaccess = unified_record_access(folio);
	unified_stats_record_access(is_reaccess, unified_is_sequential(folio));

	// Update LHD-specific fields
	u64 age = get_age(data);
	struct lhd_class *cls = get_class(data);
	if (!cls) {
		bpf_printk("cache_ext: Failed to get class\n");
		return;
	}

	data->data.lhd.last_last_hit_age = data->data.lhd.last_hit_age;
	data->data.lhd.last_hit_age = age;
	data->last_access_ns = bpf_ktime_get_ns();

	u64 *hits = cls->hits + age;

	__sync_fetch_and_add(hits, 1 * HIT_SCALING_FACTOR);

	__sync_fetch_and_add(&timestamp, 1);

	if (__sync_sub_and_fetch(&next_reconfiguration, 1) == 0) {
		next_reconfiguration = REQS_PER_RECONFIG;
		num_reconfigurations++;

		// Submit reconfigure event to ring buffer
		if (bpf_ringbuf_output(&events, &num_reconfigurations, sizeof(num_reconfigurations), 0))
			bpf_printk("cache_ext: Failed to submit reconfigure event\n");
	}
}

void BPF_STRUCT_OPS(lhd_folio_evicted, struct folio *folio) {
	if (!lhd_initialized)
		return;

	u64 age, hit_density, *evictions;
	struct lhd_class *cls;

	if (bpf_cache_ext_list_del(folio)) {
		bpf_printk("cache_ext: Failed to delete folio from lhd_list\n");
		return;
	}

	struct unified_folio_metadata *data = unified_get_metadata(folio);
	if (!data) {
		return;
	}

	age = get_age(data);
	cls = get_class(data);
	if (!cls) {
		bpf_printk("cache_ext: evicted: Failed to get class\n");
		goto cleanup;
	}

	evictions = cls->evictions + age;

	__sync_fetch_and_add(evictions, 1 * HIT_SCALING_FACTOR);

	__sync_fetch_and_sub(&num_objects, 1);

	// Add to ghost for reaccess detection
	u8 tier = unified_access_count_to_tier(data->access_count);
	unified_add_ghost(folio, POLICY_ID_LHD, tier);
	unified_stats_record_eviction();

	// Open-coded get_hit_density()
	hit_density = cls->hit_densities[age];
	ewma_victim_hit_density = ewma_decay(ewma_victim_hit_density) + rem_ewma_decay(hit_density);

cleanup:
	// Remove folio metadata
	unified_delete_metadata(folio);
}

void BPF_STRUCT_OPS(lhd_folio_added, struct folio *folio) {
	if (!lhd_initialized)
		return;

	if (!is_folio_relevant(folio))
		return;

	if (bpf_cache_ext_list_add_tail(lhd_list, folio)) {
		bpf_printk("cache_ext: added: Failed to add folio to lhd_list\n");
		return;
	}

	// Check ghost for reaccess
	struct ghost_metadata ghost;
	bool from_ghost = unified_pop_ghost(folio, &ghost);
	
	// Create unified metadata
	if (unified_create_metadata(folio, POLICY_ID_LHD, 0)) {
		bpf_cache_ext_list_del(folio);
		bpf_printk("cache_ext: added: Failed to create folio metadata\n");
		return;
	}

	struct unified_folio_metadata *meta = unified_get_metadata(folio);
	if (!meta) {
		bpf_cache_ext_list_del(folio);
		return;
	}

	// Initialize LHD-specific fields
	meta->data.lhd.last_hit_age = 0;
	meta->data.lhd.last_last_hit_age = MAX_AGE;
	meta->data.lhd.app_class = DEFAULT_APP_ID % APP_CLASSES;
	
	if (from_ghost) {
		meta->flags |= UNIFIED_FLAG_FROM_GHOST;
		unified_stats_record_ghost_hit();
	} else {
		unified_stats_record_unique_page();
	}

	__sync_fetch_and_add(&timestamp, 1);

	__sync_fetch_and_add(&num_objects, 1);

	if (__sync_sub_and_fetch(&next_reconfiguration, 1) == 0) {
		next_reconfiguration = REQS_PER_RECONFIG;
		num_reconfigurations++;

		// Submit reconfigure event to ring buffer
		if (bpf_ringbuf_output(&events, &num_reconfigurations, sizeof(num_reconfigurations), 0))
			bpf_printk("cache_ext: added: Failed to submit reconfigure event\n");
	}
}

SEC(".struct_ops.link")
struct cache_ext_ops lhd_ops = {
	.init = (void *)lhd_init,
	.evict_folios = (void *)lhd_evict_folios,
	.folio_accessed = (void *)lhd_folio_accessed,
	.folio_evicted = (void *)lhd_folio_evicted,
	.folio_added = (void *)lhd_folio_added,
};
