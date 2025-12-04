#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "cacheext_api.h"
#include "dir_watcher.h"

static int str_eq_ci(const char *a, const char *b) {
	if (!a || !b) return 0;
	for (; *a && *b; a++, b++) {
		char ca = (*a >= 'A' && *a <= 'Z') ? (char)(*a - 'A' + 'a') : *a;
		char cb = (*b >= 'A' && *b <= 'Z') ? (char)(*b - 'A' + 'a') : *b;
		if (ca != cb) return 0;
	}
	return *a == *b;
}

bool cacheext_policy_from_string(const char *name, cacheext_policy_t *out) {
	if (!name || !out) return false;
	if (str_eq_ci(name, "fifo")) { *out = CACHEEXT_POLICY_FIFO; return true; }
	if (str_eq_ci(name, "mru")) { *out = CACHEEXT_POLICY_MRU; return true; }
	if (str_eq_ci(name, "mglru")) { *out = CACHEEXT_POLICY_MGLRU; return true; }
	if (str_eq_ci(name, "lhd")) { *out = CACHEEXT_POLICY_LHD; return true; }
	if (str_eq_ci(name, "s3fifo")) { *out = CACHEEXT_POLICY_S3FIFO; return true; }
	if (str_eq_ci(name, "sampling")) { *out = CACHEEXT_POLICY_SAMPLING; return true; }
	if (str_eq_ci(name, "get_scan") || str_eq_ci(name, "get-scan")) { *out = CACHEEXT_POLICY_GET_SCAN; return true; }
	return false;
}

#include "cache_ext_fifo.skel.h"
#include "cache_ext_mru.skel.h"
#include "cache_ext_mglru.skel.h"
#include "cache_ext_lhd.bpf.h"
#include "cache_ext_lhd.skel.h"
#include "cache_ext_s3fifo.skel.h"
#include "cache_ext_sampling.skel.h"
#include "cache_ext_get_scan.skel.h"

struct active_state {
	cacheext_policy_t policy;
	int cgroup_fd;  // -1 when not in use

	struct bpf_link *link;

	struct cache_ext_fifo_bpf *fifo;
	struct cache_ext_mru_bpf *mru;
	struct cache_ext_mglru_bpf *mglru;
	struct cache_ext_lhd_bpf *lhd;
	struct cache_ext_s3fifo_bpf *s3fifo;
	struct cache_ext_sampling_bpf *sampling;
	struct cache_ext_get_scan_bpf *get_scan;

	struct ring_buffer *lhd_events;
	int lhd_reconfig_prog_fd;

	bool get_scan_pinned;
};

struct req_params {
	cacheext_policy_t policy;
	char cgroup_path[PATH_MAX];
	char watch_dir[PATH_MAX];
	unsigned long cgroup_size_bytes;
};

static struct {
	pthread_mutex_t mu;
	pthread_cond_t cv;
	pthread_t th;
	bool th_started;
	bool stopping;
	struct active_state cur;

	// requested change
	bool has_req;
	struct req_params req;
	int req_result; // result code for synchronous wait
	bool req_done;
} g_mgr = {
	.mu = PTHREAD_MUTEX_INITIALIZER,
	.cv = PTHREAD_COND_INITIALIZER,
	.cur = { .cgroup_fd = -1 },
};

static int realpath_128(const char *in, char out_path[PATH_MAX]) {
	if (!in) return EINVAL;
	if (realpath(in, out_path) == NULL) return errno ? errno : -1;
	if (strlen(out_path) > 128) return ENAMETOOLONG;
	return 0;
}

static void detach_current_locked(struct active_state *st) {
	if (st->policy == CACHEEXT_POLICY_NONE) return;

	switch (st->policy) {
	case CACHEEXT_POLICY_FIFO:
		if (st->fifo) {
			bpf_link__destroy(st->link);
			cache_ext_fifo_bpf__destroy(st->fifo);
		}
		break;
	case CACHEEXT_POLICY_MRU:
		if (st->mru) {
			bpf_link__destroy(st->link);
			cache_ext_mru_bpf__destroy(st->mru);
		}
		break;
	case CACHEEXT_POLICY_MGLRU:
		if (st->mglru) {
			bpf_link__destroy(st->link);
			cache_ext_mglru_bpf__destroy(st->mglru);
		}
		break;
	case CACHEEXT_POLICY_LHD:
		if (st->lhd_events) {
			ring_buffer__free(st->lhd_events);
			st->lhd_events = NULL;
		}
		if (st->lhd) {
			bpf_link__destroy(st->link);
			cache_ext_lhd_bpf__destroy(st->lhd);
		}
		break;
	case CACHEEXT_POLICY_S3FIFO:
		if (st->s3fifo) {
			bpf_link__destroy(st->link);
			cache_ext_s3fifo_bpf__destroy(st->s3fifo);
		}
		break;
	case CACHEEXT_POLICY_SAMPLING:
		if (st->sampling) {
			bpf_link__destroy(st->link);
			cache_ext_sampling_bpf__destroy(st->sampling);
		}
		break;
	case CACHEEXT_POLICY_GET_SCAN:
		if (st->get_scan) {
			if (st->get_scan_pinned) {
				(void)bpf_map__unpin(st->get_scan->maps.scan_pids, "/sys/fs/bpf/cache_ext/scan_pids");
			}
			bpf_link__destroy(st->link);
			cache_ext_get_scan_bpf__destroy(st->get_scan);
			st->get_scan_pinned = false;
		}
		break;
	default:
		break;
	}

	if (st->cgroup_fd >= 0) {
		close(st->cgroup_fd);
		st->cgroup_fd = -1;
	}

	memset(&st->link, 0, sizeof(*&st->link));
	st->fifo = NULL;
	st->mru = NULL;
	st->mglru = NULL;
	st->lhd = NULL;
	st->s3fifo = NULL;
	st->sampling = NULL;
	st->get_scan = NULL;
	st->policy = CACHEEXT_POLICY_NONE;
}

static int attach_fifo(struct active_state *st, const char *cgroup_path, const char *watch_dir) {
	char watch_dir_full[PATH_MAX];
	int rc = realpath_128(watch_dir, watch_dir_full);
	if (rc) return rc;

	st->cgroup_fd = open(cgroup_path, O_RDONLY);
	if (st->cgroup_fd < 0) return errno ? errno : -1;

	st->fifo = cache_ext_fifo_bpf__open();
	if (!st->fifo) return ENOMEM;

	if (cache_ext_fifo_bpf__load(st->fifo)) return EIO;

	if (initialize_watch_dir_map(watch_dir_full, bpf_map__fd(st->fifo->maps.inode_watchlist), true))
		return EIO;

	st->link = bpf_map__attach_cache_ext_ops(st->fifo->maps.fifo_ops, st->cgroup_fd);
	if (!st->link) return EIO;

	if (cache_ext_fifo_bpf__attach(st->fifo)) return EIO;

	st->policy = CACHEEXT_POLICY_FIFO;
	return 0;
}

static int attach_mru(struct active_state *st, const char *cgroup_path, const char *watch_dir) {
	char watch_dir_full[PATH_MAX];
	int rc = realpath_128(watch_dir, watch_dir_full);
	if (rc) return rc;

	st->cgroup_fd = open(cgroup_path, O_RDONLY);
	if (st->cgroup_fd < 0) return errno ? errno : -1;

	st->mru = cache_ext_mru_bpf__open();
	if (!st->mru) return ENOMEM;

	if (cache_ext_mru_bpf__load(st->mru)) return EIO;

	if (initialize_watch_dir_map(watch_dir_full, bpf_map__fd(st->mru->maps.inode_watchlist), true))
		return EIO;

	st->link = bpf_map__attach_cache_ext_ops(st->mru->maps.mru_ops, st->cgroup_fd);
	if (!st->link) return EIO;

	// No extra attach step in original beyond waiting
	st->policy = CACHEEXT_POLICY_MRU;
	return 0;
}

static int attach_mglru(struct active_state *st, const char *cgroup_path, const char *watch_dir) {
	char watch_dir_full[PATH_MAX];
	int rc = realpath_128(watch_dir, watch_dir_full);
	if (rc) return rc;

	st->cgroup_fd = open(cgroup_path, O_RDONLY);
	if (st->cgroup_fd < 0) return errno ? errno : -1;

	st->mglru = cache_ext_mglru_bpf__open();
	if (!st->mglru) return ENOMEM;

	st->mglru->rodata->watch_dir_path_len = strlen(watch_dir_full);
	strcpy(st->mglru->rodata->watch_dir_path, watch_dir_full);

	if (cache_ext_mglru_bpf__load(st->mglru)) return EIO;

	if (initialize_watch_dir_map(watch_dir_full, bpf_map__fd(st->mglru->maps.inode_watchlist), false))
		return EIO;

	st->link = bpf_map__attach_cache_ext_ops(st->mglru->maps.mglru_ops, st->cgroup_fd);
	if (!st->link) return EIO;

	if (cache_ext_mglru_bpf__attach(st->mglru)) return EIO;

	st->policy = CACHEEXT_POLICY_MGLRU;
	return 0;
}

static int lhd_handle_event(void *ctx, void *data, size_t data_sz) {
	(void)data;
	(void)data_sz;
	int fd = *(int *)ctx;
	struct bpf_test_run_opts opts = { .sz = sizeof(opts) };
	int ret = bpf_prog_test_run_opts(fd, &opts);
	return ret;
}

static int attach_lhd(struct active_state *st, const char *cgroup_path, const char *watch_dir) {
	char watch_dir_full[PATH_MAX];
	int rc = realpath_128(watch_dir, watch_dir_full);
	if (rc) return rc;

	st->cgroup_fd = open(cgroup_path, O_RDONLY);
	if (st->cgroup_fd < 0) return errno ? errno : -1;

	st->lhd = cache_ext_lhd_bpf__open();
	if (!st->lhd) return ENOMEM;

	watch_dir_path_len_map(st->lhd) = strlen(watch_dir_full);
	strcpy(watch_dir_path_map(st->lhd), watch_dir_full);

	if (cache_ext_lhd_bpf__load(st->lhd)) return EIO;

	if (initialize_watch_dir_map(watch_dir_full, bpf_map__fd(inode_watchlist_map(st->lhd)), false))
		return EIO;

	st->lhd_reconfig_prog_fd = bpf_program__fd(st->lhd->progs.reconfigure);
	st->lhd_events = ring_buffer__new(bpf_map__fd(st->lhd->maps.events), lhd_handle_event, &st->lhd_reconfig_prog_fd, NULL);
	if (!st->lhd_events) return EIO;

	st->link = bpf_map__attach_cache_ext_ops(st->lhd->maps.lhd_ops, st->cgroup_fd);
	if (!st->link) return EIO;

	if (cache_ext_lhd_bpf__attach(st->lhd)) return EIO;

	st->policy = CACHEEXT_POLICY_LHD;
	return 0;
}

static int attach_s3fifo(struct active_state *st, const char *cgroup_path, const char *watch_dir, unsigned long cgroup_size_bytes) {
	char watch_dir_full[PATH_MAX];
	int rc = realpath_128(watch_dir, watch_dir_full);
	if (rc) return rc;

	st->cgroup_fd = open(cgroup_path, O_RDONLY);
	if (st->cgroup_fd < 0) return errno ? errno : -1;

	st->s3fifo = cache_ext_s3fifo_bpf__open();
	if (!st->s3fifo) return ENOMEM;

	const uint64_t page_size = 4096;
	st->s3fifo->rodata->cache_size = cgroup_size_bytes / page_size;

	if (bpf_map__set_max_entries(st->s3fifo->maps.ghost_map, st->s3fifo->rodata->cache_size))
		return EIO;

	watch_dir_path_len_map(st->s3fifo) = strlen(watch_dir_full);
	strcpy(watch_dir_path_map(st->s3fifo), watch_dir_full);

	if (cache_ext_s3fifo_bpf__load(st->s3fifo)) return EIO;

	if (initialize_watch_dir_map(watch_dir_full, bpf_map__fd(inode_watchlist_map(st->s3fifo)), true))
		return EIO;

	st->link = bpf_map__attach_cache_ext_ops(st->s3fifo->maps.s3fifo_ops, st->cgroup_fd);
	if (!st->link) return EIO;

	if (cache_ext_s3fifo_bpf__attach(st->s3fifo)) return EIO;

	st->policy = CACHEEXT_POLICY_S3FIFO;
	return 0;
}

static int attach_sampling(struct active_state *st, const char *cgroup_path, const char *watch_dir) {
	char watch_dir_full[PATH_MAX];
	int rc = realpath_128(watch_dir, watch_dir_full);
	if (rc) return rc;

	st->cgroup_fd = open(cgroup_path, O_RDONLY);
	if (st->cgroup_fd < 0) return errno ? errno : -1;

	st->sampling = cache_ext_sampling_bpf__open();
	if (!st->sampling) return ENOMEM;

	st->sampling->rodata->watch_dir_path_len = strlen(watch_dir_full);
	strcpy(st->sampling->rodata->watch_dir_path, watch_dir_full);

	if (cache_ext_sampling_bpf__load(st->sampling)) return EIO;

	if (initialize_watch_dir_map(watch_dir_full, bpf_map__fd(st->sampling->maps.inode_watchlist), true))
		return EIO;

	st->link = bpf_map__attach_cache_ext_ops(st->sampling->maps.sampling_ops, st->cgroup_fd);
	if (!st->link) return EIO;

	if (cache_ext_sampling_bpf__attach(st->sampling)) return EIO;

	st->policy = CACHEEXT_POLICY_SAMPLING;
	return 0;
}

static int attach_get_scan(struct active_state *st, const char *cgroup_path, const char *watch_dir) {
	char watch_dir_full[PATH_MAX];
	int rc = realpath_128(watch_dir, watch_dir_full);
	if (rc) return rc;

	st->cgroup_fd = open(cgroup_path, O_RDONLY);
	if (st->cgroup_fd < 0) return errno ? errno : -1;

	st->get_scan = cache_ext_get_scan_bpf__open();
	if (!st->get_scan) return ENOMEM;

	st->get_scan->rodata->watch_dir_path_len = strlen(watch_dir_full);
	strcpy(st->get_scan->rodata->watch_dir_path, watch_dir_full);

	if (cache_ext_get_scan_bpf__load(st->get_scan)) return EIO;

	if (initialize_watch_dir_map(watch_dir_full, bpf_map__fd(st->get_scan->maps.inode_watchlist), false))
		return EIO;

	if (bpf_map__pin(st->get_scan->maps.scan_pids, "/sys/fs/bpf/cache_ext/scan_pids") < 0)
		return EIO;
	st->get_scan_pinned = true;

	st->link = bpf_map__attach_cache_ext_ops(st->get_scan->maps.sampling_ops, st->cgroup_fd);
	if (!st->link) return EIO;

	if (cache_ext_get_scan_bpf__attach(st->get_scan)) return EIO;

	st->policy = CACHEEXT_POLICY_GET_SCAN;
	return 0;
}

static int attach_policy(struct active_state *st, const struct req_params *p) {
	if (p->policy == CACHEEXT_POLICY_NONE) {
		return 0;
	}
	switch (p->policy) {
	case CACHEEXT_POLICY_FIFO:
		return attach_fifo(st, p->cgroup_path, p->watch_dir);
	case CACHEEXT_POLICY_MRU:
		return attach_mru(st, p->cgroup_path, p->watch_dir);
	case CACHEEXT_POLICY_MGLRU:
		return attach_mglru(st, p->cgroup_path, p->watch_dir);
	case CACHEEXT_POLICY_LHD:
		return attach_lhd(st, p->cgroup_path, p->watch_dir);
	case CACHEEXT_POLICY_S3FIFO:
		return attach_s3fifo(st, p->cgroup_path, p->watch_dir, p->cgroup_size_bytes);
	case CACHEEXT_POLICY_SAMPLING:
		return attach_sampling(st, p->cgroup_path, p->watch_dir);
	case CACHEEXT_POLICY_GET_SCAN:
		return attach_get_scan(st, p->cgroup_path, p->watch_dir);
	default:
		return EINVAL;
	}
}

static void *manager_main(void *arg) {
	(void)arg;
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	for (;;) {
		pthread_mutex_lock(&g_mgr.mu);
		while (!g_mgr.stopping && !g_mgr.has_req) {
			// If LHD is active, poll with timeout to process events while waiting.
			if (g_mgr.cur.policy == CACHEEXT_POLICY_LHD && g_mgr.cur.lhd_events) {
				pthread_mutex_unlock(&g_mgr.mu);
				(void)ring_buffer__poll(g_mgr.cur.lhd_events, 200 /*ms*/);
				pthread_mutex_lock(&g_mgr.mu);
			} else {
				pthread_cond_wait(&g_mgr.cv, &g_mgr.mu);
			}
		}
		if (g_mgr.stopping) {
			detach_current_locked(&g_mgr.cur);
			pthread_mutex_unlock(&g_mgr.mu);
			break;
		}

		struct req_params req = g_mgr.req;
		g_mgr.has_req = false;
		pthread_mutex_unlock(&g_mgr.mu);

		// Switch policy outside lock
		detach_current_locked(&g_mgr.cur);
		// Brief delay to allow kernel BPF cleanup before attaching new policy
		usleep(10000);  // 10ms
		int rc = attach_policy(&g_mgr.cur, &req);

		pthread_mutex_lock(&g_mgr.mu);
		g_mgr.req_result = rc;
		g_mgr.req_done = true;
		pthread_cond_broadcast(&g_mgr.cv);
		pthread_mutex_unlock(&g_mgr.mu);
	}
	return NULL;
}

static int ensure_thread_started(void) {
	if (g_mgr.th_started) return 0;
	int rc = pthread_create(&g_mgr.th, NULL, manager_main, NULL);
	if (rc != 0) return rc;
	g_mgr.th_started = true;
	return 0;
}

int cache_ext(const char *policy_name,
	      const char *cgroup_path,
	      const char *watch_dir,
	      unsigned long cgroup_size_bytes) {
	cacheext_policy_t p = CACHEEXT_POLICY_NONE;
	if (policy_name && !cacheext_policy_from_string(policy_name, &p)) {
		return EINVAL;
	}
	if (p != CACHEEXT_POLICY_NONE) {
		if (!cgroup_path || !watch_dir) return EINVAL;
	}

	int rc = ensure_thread_started();
	if (rc) return rc;

	pthread_mutex_lock(&g_mgr.mu);
	memset(&g_mgr.req, 0, sizeof(g_mgr.req));
	g_mgr.req.policy = p;
	if (cgroup_path) snprintf(g_mgr.req.cgroup_path, sizeof(g_mgr.req.cgroup_path), "%s", cgroup_path);
	if (watch_dir) snprintf(g_mgr.req.watch_dir, sizeof(g_mgr.req.watch_dir), "%s", watch_dir);
	g_mgr.req.cgroup_size_bytes = cgroup_size_bytes;
	g_mgr.has_req = true;
	g_mgr.req_done = false;
	pthread_cond_broadcast(&g_mgr.cv);

	while (!g_mgr.req_done) {
		pthread_cond_wait(&g_mgr.cv, &g_mgr.mu);
	}
	rc = g_mgr.req_result;
	pthread_mutex_unlock(&g_mgr.mu);
	return rc;
}

int cache_ext_shutdown(void) {
	if (!g_mgr.th_started) return 0;
	pthread_mutex_lock(&g_mgr.mu);
	g_mgr.stopping = true;
	pthread_cond_broadcast(&g_mgr.cv);
	pthread_mutex_unlock(&g_mgr.mu);
	(void)pthread_join(g_mgr.th, NULL);
	g_mgr.th_started = false;
	return 0;
}


