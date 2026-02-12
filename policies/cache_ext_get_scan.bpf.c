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

enum ListType {
    LIST_GENERAL,
    LIST_FOR_SCANS,
    NUM_LISTS,
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, bool);
    __uint(max_entries, 100);
} scan_pids SEC(".maps");

static inline bool is_scanning_pid() {
	__u64 pid = bpf_get_current_pid_tgid();
	pid = pid & 0xFFFFFFFF;
	u8 *ret = bpf_map_lookup_elem(&scan_pids, &pid);
	if (ret != NULL) {
		return true;
	}
	return false;
}

#define MAX_PAGES (1 << 20)
#define GET_SCAN_FLAG_TOUCHED_BY_SCAN  (1 << 8)

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, NUM_LISTS);
} sampling_list_map SEC(".maps");

#define MAX_STAT_NAME_LEN 256

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, char[MAX_STAT_NAME_LEN]);
	__type(value, s64);
	__uint(max_entries, 256);
} stats SEC(".maps");

char STAT_SCAN_PAGES[MAX_STAT_NAME_LEN] = "scan_pages";
char STAT_TOTAL_PAGES[MAX_STAT_NAME_LEN] = "total_pages";
char STAT_EVICTED_SCAN_PAGES[MAX_STAT_NAME_LEN] = "evicted_scan_pages";
char STAT_EVICTED_TOTAL_PAGES[MAX_STAT_NAME_LEN] = "evicted_total_pages";
char STAT_INSERTED_SCAN_PAGES[MAX_STAT_NAME_LEN] = "inserted_scan_pages";
char STAT_INSERTED_TOTAL_PAGES[MAX_STAT_NAME_LEN] = "inserted_total_pages";
char STAT_ACCESSED_SCAN_PAGES[MAX_STAT_NAME_LEN] = "accessed_scan_pages";
char STAT_ACCESSED_TOTAL_PAGES[MAX_STAT_NAME_LEN] = "accessed_total_pages";

static s64 scan_pages = 0;
static volatile bool get_scan_initialized = false;

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
#endif
}

inline u64 get_sampling_list(enum ListType list_type)
{
	int map_key = (int) list_type;
	u64 *sampling_list;
	sampling_list = bpf_map_lookup_elem(&sampling_list_map, &map_key);
	if (!sampling_list) {
		return 0;
	}
	return *sampling_list;
}

inline bool is_folio_relevant(struct folio *folio)
{
	if (!folio || !folio->mapping || !folio->mapping->host)
		return false;
	return inode_in_watchlist(folio->mapping->host->i_ino);
}

static int get_scan_inherit_callback(int idx, struct cache_ext_list_node *node)
{
	struct unified_folio_metadata *meta = unified_get_metadata(node->folio);
	
	if (!meta) {
		if (unified_create_metadata_with_freq(node->folio, POLICY_ID_GET_SCAN, 0, 1))
			return 2;
		return 0;
	}
	
	meta->policy_id = POLICY_ID_GET_SCAN;
	meta->flags |= UNIFIED_FLAG_INHERITED;
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(mixed_init, struct mem_cgroup *memcg)
{
	int ret;
	dbg_printk("cache_ext: Hi from the mixed_init hook! :D\n");
	for (enum ListType list_type = 0; list_type < NUM_LISTS; list_type++) {
		u64 sampling_list = bpf_cache_ext_ds_registry_new_list(memcg);
		if (sampling_list == 0) {
			bpf_printk("cache_ext: Failed to create sampling_list\n");
			return -1;
		}
		int map_key = list_type;
		ret = bpf_map_update_elem(&sampling_list_map, &map_key, &sampling_list, BPF_ANY);
		if (ret != 0) {
			bpf_printk("cache_ext: Failed to update sampling_list_map\n");
			return -1;
		}
	}

	bool has_pages = bpf_cache_ext_inherit_has_pages(memcg);
	u64 inherit_count = bpf_cache_ext_inherit_get_count(memcg);
	
	if (has_pages && inherit_count > 0) {
		u64 general_list = get_sampling_list(LIST_GENERAL);
		if (general_list) {
			bpf_cache_ext_inherit_iterate(memcg, general_list, get_scan_inherit_callback, 0);
		}
	}

	get_scan_initialized = true;
	return 0;
}

void BPF_STRUCT_OPS(mixed_folio_added, struct folio *folio)
{
	if (!get_scan_initialized)
		return;
	if (!is_folio_relevant(folio))
		return;

    enum ListType list_type = LIST_GENERAL;
	bool touched_by_scan = is_scanning_pid();
	if (touched_by_scan)
        list_type = LIST_FOR_SCANS;

    u64 sampling_list = get_sampling_list(list_type);
	if (sampling_list == 0)
		return;

	if (bpf_cache_ext_list_add_tail(sampling_list, folio))
		return;

	update_stat(&STAT_TOTAL_PAGES, 1);
	if (touched_by_scan) {
		__sync_fetch_and_add(&scan_pages, 1);
		update_stat(&STAT_INSERTED_SCAN_PAGES, 1);
	}

	struct ghost_metadata ghost;
	bool from_ghost = unified_pop_ghost(folio, &ghost);

	if (unified_create_metadata_with_freq(folio, POLICY_ID_GET_SCAN, list_type, 1)) {
		bpf_cache_ext_list_del(folio);
		return;
	}
	
	struct unified_folio_metadata *meta = unified_get_metadata(folio);
	if (meta) {
		if (touched_by_scan)
			meta->flags |= GET_SCAN_FLAG_TOUCHED_BY_SCAN;
		if (from_ghost) {
			meta->flags |= UNIFIED_FLAG_FROM_GHOST;
			unified_stats_record_ghost_hit();
		} else {
			unified_stats_record_unique_page();
		}
	}
}

void BPF_STRUCT_OPS(mixed_folio_accessed, struct folio *folio)
{
	if (!get_scan_initialized)
		return;
	if (!is_folio_relevant(folio))
		return;
	
	struct unified_folio_metadata *meta = unified_get_metadata(folio);
	if (!meta) {
		if (unified_create_metadata_with_freq(folio, POLICY_ID_GET_SCAN, 0, 1))
			return;
		meta = unified_get_metadata(folio);
		if (!meta)
			return;
		}
	
	bool is_reaccess = unified_record_access(folio);
	unified_stats_record_access(is_reaccess, unified_is_sequential(folio));

	update_stat(&STAT_ACCESSED_TOTAL_PAGES, 1);
	if (meta->flags & GET_SCAN_FLAG_TOUCHED_BY_SCAN)
		update_stat(&STAT_ACCESSED_SCAN_PAGES, 1);
	
	__sync_fetch_and_add(&meta->data.mglru.freq, 1);
}

void BPF_STRUCT_OPS(mixed_folio_evicted, struct folio *folio)
{
	if (!get_scan_initialized)
		return;

	bpf_cache_ext_list_del(folio);

	struct unified_folio_metadata *meta = unified_get_metadata(folio);
	bool touched_by_scan = false;
	if (meta) {
		touched_by_scan = (meta->flags & GET_SCAN_FLAG_TOUCHED_BY_SCAN) != 0;
		unified_add_ghost(folio, POLICY_ID_GET_SCAN, touched_by_scan ? 1 : 0);
		unified_stats_record_eviction();
		unified_delete_metadata(folio);
	}
	
	if (touched_by_scan) {
		__sync_fetch_and_sub(&scan_pages, 1);
		update_stat(&STAT_EVICTED_SCAN_PAGES, 1);
	}
	update_stat(&STAT_TOTAL_PAGES, -1);
	update_stat(&STAT_EVICTED_TOTAL_PAGES, 1);
}

static inline bool is_last_page_in_file(struct folio *folio)
{
	struct address_space *mapping = folio->mapping;
	if (!mapping)
		return false;
	struct inode *inode = mapping->host;
	if (!inode)
		return false;
	if (folio_test_large(folio) || folio_test_hugetlb(folio))
		return false;
	unsigned long long file_size = i_size_read(inode);
	unsigned long long page_index = folio_index(folio);
	unsigned long long page_size = 4096;
	unsigned long long last_page_index = (file_size + page_size - 1) / page_size - 1;
	return page_index == last_page_index;
}

static s64 bpf_lfu_score_fn(struct cache_ext_list_node *a)
{
	struct unified_folio_metadata *meta = unified_get_metadata(a->folio);
	if (!meta)
		return INT64_MAX;
	
	s64 score = meta->data.mglru.freq;
	if (is_last_page_in_file(a->folio))
		score += 100000;
	
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
		return INT64_MAX;
	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
		return INT64_MAX;
	
	return score;
}

void BPF_STRUCT_OPS(mixed_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	if (!get_scan_initialized)
		return;

	int sampling_rate = 5;
	s64 num_scan_pages = scan_pages;
	if (num_scan_pages == 0)
		return;

	enum ListType list_type = LIST_FOR_SCANS;
	if (num_scan_pages < 1000 * sampling_rate)
		list_type = LIST_GENERAL;

	u64 sampling_list = get_sampling_list(list_type);
	if (sampling_list == 0)
		return;
	
	struct sampling_options sampling_opts = { .sample_size = sampling_rate };
	bpf_cache_ext_list_sample(memcg, sampling_list, bpf_lfu_score_fn, &sampling_opts, eviction_ctx);
}

SEC(".struct_ops.link")
struct cache_ext_ops sampling_ops = {
	.init = (void *)mixed_init,
	.evict_folios = (void *)mixed_evict_folios,
	.folio_accessed = (void *)mixed_folio_accessed,
	.folio_evicted = (void *)mixed_folio_evicted,
	.folio_added = (void *)mixed_folio_added,
};
