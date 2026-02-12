#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"
#include "unified_metadata.bpf.h"

char _license[] SEC("license") = "GPL";

#define ENOENT		2  /* include/uapi/asm-generic/errno-base.h */
#define INT64_MAX	(9223372036854775807LL)

// Set from userspace. In terms of number of pages.
#define CACHE_SIZE (((1ull << 20) * 200) / 4096)
const volatile size_t cache_size = 0;

// S3FIFO list indices
#define S3FIFO_LIST_SMALL  0
#define S3FIFO_LIST_MAIN   1

static u64 main_list;
static u64 small_list;
static volatile bool s3fifo_initialized = false;

/*
 * This is an approximate value based on what we choose to evict, not what is
 * actually evicted.
 */
static s64 small_list_size = 0;
static s64 main_list_size = 0;

static u64 folio_added_count = 0;
static u64 folio_relevant_count = 0;

static inline bool is_folio_relevant(struct folio *folio) {
	if (!folio || !folio->mapping || !folio->mapping->host)
		return false;

	u64 ino = folio->mapping->host->i_ino;
	bool relevant = inode_in_watchlist(ino);
	
	__sync_fetch_and_add(&folio_added_count, 1);
	if (relevant) {
		__sync_fetch_and_add(&folio_relevant_count, 1);
	}
	
	return relevant;
}

/*
 * Callback for inherit_iterate: classify inherited pages.
 * Returns:
 *   0 = continue, move to target_list (small_list)
 *   1 = stop iteration
 *   2 = skip this node
 */
static int s3fifo_inherit_callback(int idx, struct cache_ext_list_node *node)
{
	struct unified_folio_metadata *meta = unified_get_metadata(node->folio);
	
	if (!meta) {
		// Create new metadata for inherited page
		if (unified_create_metadata_with_freq(node->folio, POLICY_ID_S3FIFO, 
						       S3FIFO_LIST_SMALL, 1)) {
			return 2;  // Skip if we can't create metadata
		}
		__sync_fetch_and_add(&small_list_size, 1);
		return 0;
	}
	
	// Convert previous policy's metadata to S3FIFO
	meta->policy_id = POLICY_ID_S3FIFO;
	meta->flags |= UNIFIED_FLAG_INHERITED;
	
	// Convert access_count to S3FIFO frequency
	meta->data.mglru.freq = unified_access_count_to_freq(meta->access_count);
	
	// Check ghost: if page was evicted and came back, it goes to main
	struct ghost_metadata ghost;
	if (unified_pop_ghost(node->folio, &ghost)) {
		meta->flags |= (UNIFIED_FLAG_IN_MAIN | UNIFIED_FLAG_FROM_GHOST);
		meta->list_idx = S3FIFO_LIST_MAIN;
		unified_stats_record_ghost_hit();
		__sync_fetch_and_add(&main_list_size, 1);
		// Return 1 to indicate main_list (we'll handle this specially)
		// Actually, inherit_iterate moves to target_list, so we use small first
		// For main list placement, we need to handle this differently
		return 0;  // For now, all go to small_list during inheritance
	}
	
	meta->list_idx = S3FIFO_LIST_SMALL;
	meta->flags &= ~UNIFIED_FLAG_IN_MAIN;
	__sync_fetch_and_add(&small_list_size, 1);
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(s3fifo_init, struct mem_cgroup *memcg)
{
	bpf_printk("cache_ext: S3FIFO init starting, memcg=%p\n", memcg);
	
	// 1. Create lists
	main_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (main_list == 0) {
		bpf_printk("cache_ext: S3FIFO Failed to create main_list\n");
		return -1;
	}
	bpf_printk("cache_ext: S3FIFO Created main_list: %llu\n", main_list);

	small_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (small_list == 0) {
		bpf_printk("cache_ext: S3FIFO Failed to create small_list\n");
		return -1;
	}
	bpf_printk("cache_ext: S3FIFO Created small_list: %llu\n", small_list);

	// 2. Check for inherited pages from previous policy
	bool has_pages = bpf_cache_ext_inherit_has_pages(memcg);
	u64 inherit_count = bpf_cache_ext_inherit_get_count(memcg);
	bpf_printk("cache_ext: S3FIFO inherit check: has_pages=%d, count=%llu\n", 
		   has_pages, inherit_count);

	// 3. Inherit pages if available
	if (has_pages && inherit_count > 0) {
		bpf_printk("cache_ext: S3FIFO inheriting %llu pages\n", inherit_count);
		
		int processed = bpf_cache_ext_inherit_iterate(
			memcg,
			small_list,              // target list
			s3fifo_inherit_callback, // callback for metadata creation
			0                        // 0 = process all pages
		);
		
		bpf_printk("cache_ext: S3FIFO actually inherited %d pages\n", processed);
	} else {
		bpf_printk("cache_ext: S3FIFO no pages to inherit\n");
	}

	// Mark as initialized - MUST be last!
	s3fifo_initialized = true;
	bpf_printk("cache_ext: S3FIFO init complete\n");
	
	return 0;
}

static s64 bpf_s3fifo_score_main_fn(struct cache_ext_list_node *a) {
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
		return INT64_MAX;

	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
		return INT64_MAX;

	struct unified_folio_metadata *data = unified_get_metadata(a->folio);
	if (!data) {
		bpf_printk("cache_ext: score_fn: Failed to get metadata\n");
		return INT64_MAX;
	}

	__sync_fetch_and_sub(&data->data.mglru.freq, 1);
	s64 freq = data->data.mglru.freq;
	if (freq < 0)
		data->data.mglru.freq = 0;

	return freq;
}

static int bpf_s3fifo_score_small_fn(int idx, struct cache_ext_list_node *a)
{
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
		return CACHE_EXT_CONTINUE_ITER;

	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
		return CACHE_EXT_CONTINUE_ITER;

	struct unified_folio_metadata *data = unified_get_metadata(a->folio);
	if (!data) {
		bpf_printk("cache_ext: score_fn: Failed to get metadata\n");
		return CACHE_EXT_CONTINUE_ITER;
	}

	// Move to main list if freq > 1
	if (data->data.mglru.freq > 1) {
		data->flags |= UNIFIED_FLAG_IN_MAIN;
		data->list_idx = S3FIFO_LIST_MAIN;
		return CACHE_EXT_CONTINUE_ITER;
	}

	// Else, evict
	return CACHE_EXT_EVICT_NODE;
}

static void evict_main(struct cache_ext_eviction_ctx *eviction_ctx, struct mem_cgroup *memcg)
{
	struct sampling_options opts = {
		.sample_size = 10,
	};

	if (bpf_cache_ext_list_sample(memcg, main_list, bpf_s3fifo_score_main_fn, &opts,
				      eviction_ctx)) {
		bpf_printk("cache_ext: evict: Failed to sample main_list\n");
		return;
	}
}

#define MAIN_ITER_FN(id) 								\
static int bpf_s3fifo_score_main_iter_fn_##id(int idx, struct cache_ext_list_node *a) 	\
{ 											\
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio)) 		\
		return CACHE_EXT_CONTINUE_ITER; 					\
 											\
	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio)) 		\
		return CACHE_EXT_CONTINUE_ITER; 					\
 											\
	struct unified_folio_metadata *data = unified_get_metadata(a->folio); 		\
	if (!data) { 									\
		bpf_printk("cache_ext: score_fn: Failed to get metadata\n"); 		\
		return CACHE_EXT_CONTINUE_ITER; 					\
	} 										\
 											\
	__sync_fetch_and_sub(&data->data.mglru.freq, 1); 				\
	s64 freq = data->data.mglru.freq; 						\
	if (freq < id) { 								\
		return CACHE_EXT_EVICT_NODE; 						\
	} 										\
 											\
	return CACHE_EXT_CONTINUE_ITER; 						\
}

MAIN_ITER_FN(0)
MAIN_ITER_FN(1)
MAIN_ITER_FN(2)
MAIN_ITER_FN(3)

static void evict_main_iter(struct cache_ext_eviction_ctx *eviction_ctx, struct mem_cgroup *memcg)
{
	struct cache_ext_iterate_opts opts = {
		.continue_list = CACHE_EXT_ITERATE_SELF,
		.continue_mode = CACHE_EXT_ITERATE_TAIL,
		.evict_list = CACHE_EXT_ITERATE_SELF,
		.evict_mode = CACHE_EXT_ITERATE_TAIL,
	};

	if (bpf_cache_ext_list_iterate_extended(memcg, main_list, bpf_s3fifo_score_main_iter_fn_0, &opts,
						eviction_ctx) < 0) {
		bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
		return;
	}

	if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
		if (bpf_cache_ext_list_iterate_extended(memcg, main_list, bpf_s3fifo_score_main_iter_fn_1, &opts,
							eviction_ctx) < 0) {
			bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
			return;
		}
	} else {
		return;
	}

	if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
		if (bpf_cache_ext_list_iterate_extended(memcg, main_list, bpf_s3fifo_score_main_iter_fn_2, &opts,
							eviction_ctx) < 0) {
			bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
			return;
		}
	} else {
		return;
	}

	if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
		if (bpf_cache_ext_list_iterate_extended(memcg, main_list, bpf_s3fifo_score_main_iter_fn_3, &opts,
							eviction_ctx) < 0) {
			bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
			return;
		}
	}
}

static void evict_small(struct cache_ext_eviction_ctx *eviction_ctx, struct mem_cgroup *memcg)
{
	struct cache_ext_iterate_opts opts = {
		.continue_list = main_list,
		.continue_mode = CACHE_EXT_ITERATE_TAIL,
		.evict_list = CACHE_EXT_ITERATE_SELF,
		.evict_mode = CACHE_EXT_ITERATE_TAIL,
	};

	if (bpf_cache_ext_list_iterate_extended(memcg, small_list, bpf_s3fifo_score_small_fn, &opts,
						eviction_ctx) < 0) {
		bpf_printk("cache_ext: evict: Failed to iterate small_list\n");
		return;
	}

	if (__sync_fetch_and_sub(&small_list_size, opts.nr_folios_continue) < 0)
		small_list_size = 0;

	if (__sync_fetch_and_add(&main_list_size, opts.nr_folios_continue) < 0)
		main_list_size = opts.nr_folios_continue;
}

void BPF_STRUCT_OPS(s3fifo_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	if (!s3fifo_initialized)
		return;
	
	if (small_list_size >= cache_size / 15 || main_list_size <= 2 * small_list_size)
		evict_small(eviction_ctx, memcg);
	else
		evict_main_iter(eviction_ctx, memcg);
}

void BPF_STRUCT_OPS(s3fifo_folio_accessed, struct folio *folio) {
	if (!s3fifo_initialized)
		return;
	
	if (!is_folio_relevant(folio))
		return;

	struct unified_folio_metadata *data = unified_get_metadata(folio);
	if (!data) {
		bpf_printk("cache_ext: accessed: Failed to get metadata\n");
		return;
	}

	// Record access in unified metadata
	bool is_reaccess = unified_record_access(folio);
	unified_stats_record_access(is_reaccess, unified_is_sequential(folio));

	// Cap frequency at 3 (S3FIFO specific)
	__sync_fetch_and_add(&data->data.mglru.freq, 1);
	if (data->data.mglru.freq > 3)
		data->data.mglru.freq = 3;
}

void BPF_STRUCT_OPS(s3fifo_folio_evicted, struct folio *folio) {
	if (!s3fifo_initialized)
		return;

	// Remove folio from list BEFORE kernel frees it
	bpf_cache_ext_list_del(folio);

	struct unified_folio_metadata *data = unified_get_metadata(folio);
	if (!data) {
		return;
	}

	// Add to ghost map for reaccess detection
	u8 tier = (data->flags & UNIFIED_FLAG_IN_MAIN) ? S3FIFO_LIST_MAIN : S3FIFO_LIST_SMALL;
	unified_add_ghost(folio, POLICY_ID_S3FIFO, tier);
	unified_stats_record_eviction();

	if (data->flags & UNIFIED_FLAG_IN_MAIN)
		__sync_fetch_and_sub(&main_list_size, 1);
	else
		__sync_fetch_and_sub(&small_list_size, 1);

	// Delete metadata
	unified_delete_metadata(folio);
}

/*
 * If folio is in the ghost map, add to tail of main list, otherwise add to tail
 * of small list.
 */
void BPF_STRUCT_OPS(s3fifo_folio_added, struct folio *folio) {
	if (!s3fifo_initialized)
		return;
	
	if (!is_folio_relevant(folio))
		return;

	u64 list_to_add;
	u16 list_idx;
	u32 flags = 0;
	
	// Check ghost for reaccess
	struct ghost_metadata ghost;
	if (unified_pop_ghost(folio, &ghost)) {
		list_to_add = main_list;
		list_idx = S3FIFO_LIST_MAIN;
		flags = UNIFIED_FLAG_IN_MAIN | UNIFIED_FLAG_FROM_GHOST;
		__sync_fetch_and_add(&main_list_size, 1);
		unified_stats_record_ghost_hit();
	} else {
		list_to_add = small_list;
		list_idx = S3FIFO_LIST_SMALL;
		__sync_fetch_and_add(&small_list_size, 1);
		unified_stats_record_unique_page();
	}

	if (bpf_cache_ext_list_add_tail(list_to_add, folio)) {
		bpf_printk("cache_ext: added: Failed to add folio to list\n");
		return;
	}

	// Create unified metadata
	if (unified_create_metadata_with_freq(folio, POLICY_ID_S3FIFO, list_idx, 0)) {
		bpf_cache_ext_list_del(folio);
		bpf_printk("cache_ext: added: Failed to create folio metadata\n");
		return;
	}
	
	// Set flags after creation
	struct unified_folio_metadata *meta = unified_get_metadata(folio);
	if (meta) {
		meta->flags = flags;
	}
}

SEC(".struct_ops.link")
struct cache_ext_ops s3fifo_ops = {
	.init = (void *)s3fifo_init,
	.evict_folios = (void *)s3fifo_evict_folios,
	.folio_accessed = (void *)s3fifo_folio_accessed,
	.folio_evicted = (void *)s3fifo_folio_evicted,
	.folio_added = (void *)s3fifo_folio_added,
};
