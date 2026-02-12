#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"
#include "unified_metadata.bpf.h"

char _license[] SEC("license") = "GPL";


#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

// #define DEBUG
#ifdef DEBUG
#define dbg_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define dbg_printk(fmt, ...)
#endif

static u64 mru_folio_added_count = 0;
static u64 mru_folio_relevant_count = 0;
static volatile bool mru_initialized = false;

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
	u64 ino = folio->mapping->host->i_ino;
	bool res = inode_in_watchlist(ino);
	
	u64 count = __sync_fetch_and_add(&mru_folio_added_count, 1);
	if (count % 1000 == 0) {
		bpf_printk("cache_ext: MRU is_folio_relevant #%llu, ino=%llu, result=%d\n", 
			   count, ino, res);
	}
	if (res) {
		__sync_fetch_and_add(&mru_folio_relevant_count, 1);
	}
	
	return res;
}

__u64 mru_list;

/*
 * Callback for inherit_iterate: move inherited pages to MRU list
 */
static int mru_inherit_callback(int idx, struct cache_ext_list_node *node)
{
	struct unified_folio_metadata *meta = unified_get_metadata(node->folio);
	
	if (!meta) {
		// Create new metadata for inherited page
		if (unified_create_metadata(node->folio, POLICY_ID_MRU, 0)) {
			return 2;  // Skip if we can't create metadata
		}
		return 0;
	}
	
	// Convert to MRU metadata
	meta->policy_id = POLICY_ID_MRU;
	meta->flags |= UNIFIED_FLAG_INHERITED;
	meta->list_idx = 0;
	
	return 0;  // Move to target list
}

s32 BPF_STRUCT_OPS_SLEEPABLE(mru_init, struct mem_cgroup *memcg)
{
	bpf_printk("cache_ext: MRU init starting, memcg=%p\n", memcg);
	
	// 1. Create new MRU list
	mru_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (mru_list == 0) {
		bpf_printk("cache_ext: MRU Failed to create mru_list\n");
		return -1;
	}
	bpf_printk("cache_ext: MRU Created mru_list: %llu\n", mru_list);
	
	// 2. Check for inherited pages from previous policy
	bool has_pages = bpf_cache_ext_inherit_has_pages(memcg);
	u64 inherit_count = bpf_cache_ext_inherit_get_count(memcg);
	bpf_printk("cache_ext: MRU inherit check: has_pages=%d, count=%llu\n", 
		   has_pages, inherit_count);
	
	// 3. Inherit pages if available
	if (has_pages && inherit_count > 0) {
		bpf_printk("cache_ext: MRU inheriting %llu pages\n", inherit_count);
		
		// For MRU: use iterate callback to set metadata
		int processed = bpf_cache_ext_inherit_iterate(
			memcg, 
			mru_list,
			mru_inherit_callback,
			0  // 0 = all pages
		);
		bpf_printk("cache_ext: MRU actually inherited %d pages\n", processed);
	} else {
		bpf_printk("cache_ext: MRU no pages to inherit\n");
	}
	
	mru_initialized = true;
	bpf_printk("cache_ext: MRU init complete\n");
	
	return 0;
}

void BPF_STRUCT_OPS(mru_folio_added, struct folio *folio)
{
	if (!mru_initialized)
		return;

	dbg_printk("cache_ext: Hi from the mru_folio_added hook! :D\n");
	if (!is_folio_relevant(folio)) {
		return;
	}

	int ret = bpf_cache_ext_list_add(mru_list, folio);
	if (ret != 0) {
		bpf_printk("cache_ext: Failed to add folio to mru_list\n");
		return;
	}
	
	// Check ghost for reaccess
	struct ghost_metadata ghost;
	bool from_ghost = unified_pop_ghost(folio, &ghost);
	
	// Create unified metadata
	if (unified_create_metadata(folio, POLICY_ID_MRU, 0)) {
		bpf_cache_ext_list_del(folio);
		bpf_printk("cache_ext: MRU: Failed to create folio metadata\n");
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
	
	dbg_printk("cache_ext: Added folio to mru_list\n");
}

void BPF_STRUCT_OPS(mru_folio_accessed, struct folio *folio)
{
	if (!mru_initialized)
		return;

	int ret;
	dbg_printk("cache_ext: Hi from the mru_folio_accessed hook! :D\n");

	if (!is_folio_relevant(folio)) {
		return;
	}

	// Record access for reaccess tracking
	bool is_reaccess = unified_record_access(folio);
	unified_stats_record_access(is_reaccess, unified_is_sequential(folio));

	ret = bpf_cache_ext_list_move(mru_list, folio, false);
	if (ret != 0) {
		bpf_printk("cache_ext: Failed to move folio to mru_list head\n");
		return;
	}

	dbg_printk("cache_ext: Moved folio to mru_list head\n");
}

void BPF_STRUCT_OPS(mru_folio_evicted, struct folio *folio)
{
	if (!mru_initialized)
		return;

	dbg_printk("cache_ext: Hi from the mru_folio_evicted hook! :D\n");
	bpf_cache_ext_list_del(folio);
	
	// Add to ghost for reaccess detection
	struct unified_folio_metadata *meta = unified_get_metadata(folio);
	if (meta) {
		unified_add_ghost(folio, POLICY_ID_MRU, 0);
		unified_stats_record_eviction();
		unified_delete_metadata(folio);
	}
}

static int iterate_mru(int idx, struct cache_ext_list_node *node)
{
	if ((idx < 200) && (!folio_test_uptodate(node->folio) || !folio_test_lru(node->folio))) {
		return CACHE_EXT_CONTINUE_ITER;
	}
	return CACHE_EXT_EVICT_NODE;
}

void BPF_STRUCT_OPS(mru_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
	       struct mem_cgroup *memcg)
{
	if (!mru_initialized)
		return;

	dbg_printk("cache_ext: Hi from the mru_evict_folios hook! :D\n");
	int ret = bpf_cache_ext_list_iterate(memcg, mru_list, iterate_mru,
					     eviction_ctx);
	if (ret < 0) {
		bpf_printk("cache_ext: Failed to evict folios\n");
	}
	if (eviction_ctx->request_nr_folios_to_evict > eviction_ctx->nr_folios_to_evict) {
		bpf_printk("cache_ext: Didn't evict enough folios. Requested: %d, Evicted: %d\n",
			   eviction_ctx->request_nr_folios_to_evict,
			   eviction_ctx->nr_folios_to_evict);
	}
}

SEC(".struct_ops.link")
struct cache_ext_ops mru_ops = {
	.init = (void *)mru_init,
	.evict_folios = (void *)mru_evict_folios,
	.folio_accessed = (void *)mru_folio_accessed,
	.folio_evicted = (void *)mru_folio_evicted,
	.folio_added = (void *)mru_folio_added,
};
