#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"
#include "unified_metadata.bpf.h"

char _license[] SEC("license") = "GPL";

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define INT64_MAX  (9223372036854775807LL)

// #define DEBUG
#ifdef DEBUG
#define dbg_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define dbg_printk(fmt, ...)
#endif

/*
 * Maps
 */

#define MAX_PAGES (1 << 20)

__u64 sampling_list;
static volatile bool sampling_initialized = false;

#define MAX_STAT_NAME_LEN 256

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, char[MAX_STAT_NAME_LEN]);
	__type(value, s64);
	__uint(max_entries, 256);
} stats SEC(".maps");

/* App type for specific optimizations */
enum App {
	GENERIC_APP,
	LEVELDB,
};

// Keys for stats
char STAT_SCAN_PAGES[MAX_STAT_NAME_LEN] = "scan_pages";
char STAT_TOTAL_PAGES[MAX_STAT_NAME_LEN] = "total_pages";
char STAT_EVICTED_SCAN_PAGES[MAX_STAT_NAME_LEN] = "evicted_scan_pages";
char STAT_EVICTED_TOTAL_PAGES[MAX_STAT_NAME_LEN] = "evicted_total_pages";

/* Counter for list size */
const int APP_TYPE = GENERIC_APP;

inline void update_stat(char (*stat_name)[MAX_STAT_NAME_LEN], s64 delta) {
#ifdef DEBUG
	u64 *counter = bpf_map_lookup_elem(&stats, stat_name);
	if (!counter) {
		u64 zero = 0;
		bpf_map_update_elem(&stats, stat_name, &zero, BPF_NOEXIST);
		counter = bpf_map_lookup_elem(&stats, stat_name);
	}
	if (counter) {
		__sync_fetch_and_add(counter, delta);
	}
#endif // DEBUG
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
 * Callback for inherit_iterate: move inherited pages to sampling list
 */
static int sampling_inherit_callback(int idx, struct cache_ext_list_node *node)
{
	struct unified_folio_metadata *meta = unified_get_metadata(node->folio);
	
	if (!meta) {
		if (unified_create_metadata_with_freq(node->folio, POLICY_ID_SAMPLING, 0, 1)) {
			return 2;
		}
		return 0;
	}
	
	meta->policy_id = POLICY_ID_SAMPLING;
	meta->flags |= UNIFIED_FLAG_INHERITED;
	// Preserve access_count as frequency for LFU
	
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(sampling_init, struct mem_cgroup *memcg)
{
	dbg_printk("cache_ext: Hi from the sampling_init hook! :D\n");
	sampling_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (sampling_list == 0) {
		bpf_printk("cache_ext: Failed to create sampling_list\n");
		return -1;
	}
	bpf_printk("cache_ext: Created sampling_list: %llu\n", sampling_list);

	// Check for inherited pages
	bool has_pages = bpf_cache_ext_inherit_has_pages(memcg);
	u64 inherit_count = bpf_cache_ext_inherit_get_count(memcg);
	
	if (has_pages && inherit_count > 0) {
		int processed = bpf_cache_ext_inherit_iterate(
			memcg,
			sampling_list,
			sampling_inherit_callback,
			0
		);
		bpf_printk("cache_ext: Sampling inherited %d pages\n", processed);
	}

	sampling_initialized = true;
	return 0;
}

void BPF_STRUCT_OPS(sampling_folio_added, struct folio *folio)
{
	if (!sampling_initialized)
		return;

	dbg_printk("cache_ext: Hi from the sampling_folio_added hook! :D\n");
	if (!is_folio_relevant(folio)) {
		return;
	}

	int ret = bpf_cache_ext_list_add_tail(sampling_list, folio);
	if (ret != 0) {
		bpf_printk("cache_ext: Failed to add folio to sampling_list\n");
		return;
	}
	dbg_printk("cache_ext: Added folio to sampling_list\n");

	update_stat(&STAT_TOTAL_PAGES, 1);

	// Check ghost for reaccess
	struct ghost_metadata ghost;
	bool from_ghost = unified_pop_ghost(folio, &ghost);

	// Create unified metadata with freq=1 (for LFU scoring)
	if (unified_create_metadata_with_freq(folio, POLICY_ID_SAMPLING, 0, 1)) {
		bpf_cache_ext_list_del(folio);
		bpf_printk("cache_ext: Failed to create folio metadata\n");
		return;
	}
	
	if (from_ghost) {
		struct unified_folio_metadata *meta = unified_get_metadata(folio);
		if (meta) {
			meta->flags |= UNIFIED_FLAG_FROM_GHOST;
		}
		unified_stats_record_ghost_hit();
	} else {
		unified_stats_record_unique_page();
	}
}

void BPF_STRUCT_OPS(sampling_folio_accessed, struct folio *folio)
{
	if (!sampling_initialized)
		return;

	if (!is_folio_relevant(folio)) {
		return;
	}
	
	struct unified_folio_metadata *meta = unified_get_metadata(folio);
	if (!meta) {
		// Create if doesn't exist
		if (unified_create_metadata_with_freq(folio, POLICY_ID_SAMPLING, 0, 1)) {
			bpf_printk("cache_ext: Failed to create folio metadata in accessed\n");
			return;
		}
		meta = unified_get_metadata(folio);
		if (!meta) {
			return;
		}
	}
	
	// Record access for reaccess tracking
	bool is_reaccess = unified_record_access(folio);
	unified_stats_record_access(is_reaccess, unified_is_sequential(folio));
	
	// Increment frequency for LFU
	__sync_fetch_and_add(&meta->data.mglru.freq, 1);
}

void BPF_STRUCT_OPS(sampling_folio_evicted, struct folio *folio)
{
	if (!sampling_initialized)
		return;

	dbg_printk("cache_ext: Hi from the sampling_folio_evicted hook! :D\n");
	if (bpf_cache_ext_list_del(folio)) {
		dbg_printk("cache_ext: Failed to delete folio from sampling_list\n");
		return;
	}

	// Add to ghost for reaccess detection
	struct unified_folio_metadata *meta = unified_get_metadata(folio);
	if (meta) {
		unified_add_ghost(folio, POLICY_ID_SAMPLING, 0);
		unified_stats_record_eviction();
		unified_delete_metadata(folio);
	}
	
	update_stat(&STAT_TOTAL_PAGES, -1);
	update_stat(&STAT_EVICTED_TOTAL_PAGES, 1);
}

static inline bool is_last_page_in_file(struct folio *folio)
{
	struct address_space *mapping = folio->mapping;
	if (!mapping) {
		return false;
	}
	struct inode *inode = mapping->host;
	if (!inode) {
		return false;
	}
	if (folio_test_large(folio) || folio_test_hugetlb(folio)) {
		bpf_printk("cache_ext: Hugepages not supported\n");
		return false;
	}
	unsigned long long file_size = i_size_read(inode);
	unsigned long long page_index = folio_index(folio);
	unsigned long long page_size = 4096;
	unsigned long long last_page_index = (file_size + page_size - 1) / page_size - 1;
	return page_index == last_page_index;
}

static s64 bpf_lfu_score_fn(struct cache_ext_list_node *a)
{
	s64 score = 0;
	struct unified_folio_metadata *meta = unified_get_metadata(a->folio);
	if (!meta) {
		bpf_printk("cache_ext: Failed to get metadata\n");
		return INT64_MAX;
	}
	
	// Use freq as LFU score
	score = meta->data.mglru.freq;
	
	if (APP_TYPE == LEVELDB) {
		bool is_last_page = is_last_page_in_file(a->folio);
		if (is_last_page) {
			score += 100000;
		}
	}

	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio)) {
		return INT64_MAX;
	}
	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio)) {
		return INT64_MAX;
	}
	return score;
}

void BPF_STRUCT_OPS(sampling_evict_folios,
		    struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	if (!sampling_initialized)
		return;

	dbg_printk("cache_ext: Hi from the sampling_evict_folios hook! :D\n");

	struct sampling_options sampling_opts = {
		.sample_size = 20,
	};
	bpf_cache_ext_list_sample(memcg, sampling_list, bpf_lfu_score_fn,
				  &sampling_opts, eviction_ctx);
	dbg_printk("cache_ext: Evicting %d pages (%d requested)\n",
			   eviction_ctx->nr_folios_to_evict,
			   eviction_ctx->request_nr_folios_to_evict);
}

SEC(".struct_ops.link")
struct cache_ext_ops sampling_ops = {
	.init = (void *)sampling_init,
	.evict_folios = (void *)sampling_evict_folios,
	.folio_accessed = (void *)sampling_folio_accessed,
	.folio_evicted = (void *)sampling_folio_evicted,
	.folio_added = (void *)sampling_folio_added,
};
