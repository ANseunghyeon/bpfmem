#include <argp.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "cache_ext_mru.skel.h"
#include "dir_watcher.h"

char *USAGE =
	"Usage: ./cache_ext_mru --watch_dir <dir> --cgroup_path <path>\n";

struct cmdline_args {
	char *watch_dir;
	char *cgroup_path;
};

static struct argp_option options[] = { { "watch_dir", 'w', "DIR", 0,
					  "Directory to watch" },
					{ "cgroup_path", 'c', "PATH", 0,
					  "Path to cgroup (e.g., /sys/fs/cgroup/cache_ext_test)" },
					{ 0 } };

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct cmdline_args *args = state->input;
	switch (key) {
	case 'w':
		args->watch_dir = arg;
		break;
	case 'c':
		args->cgroup_path = arg;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int ret = 1;
	struct cache_ext_mru_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	int cgroup_fd = -1;
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	// Parse command line arguments
	struct cmdline_args args = { 0 };
	struct argp argp = { options, parse_opt, 0, 0 };
	argp_parse(&argp, argc, argv, 0, 0, &args);

	// Validate arguments
	if (args.watch_dir == NULL) {
		fprintf(stderr, "Missing required argument: watch_dir\n");
		return 1;
	}

	if (args.cgroup_path == NULL) {
		fprintf(stderr, "Missing required argument: cgroup_path\n");
		return 1;
	}

	// Does watch_dir exist?
	if (access(args.watch_dir, F_OK) == -1) {
		fprintf(stderr, "Directory does not exist: %s\n",
			args.watch_dir);
		return 1;
	}

	// Get full path of watch_dir
	char watch_dir_full_path[PATH_MAX];
	if (realpath(args.watch_dir, watch_dir_full_path) == NULL) {
		perror("realpath");
		return 1;
	}

	// TODO: Enable longer length
	if (strlen(watch_dir_full_path) > 128) {
		fprintf(stderr, "watch_dir path too long\n");
		return 1;
	}

	// Open cgroup directory early
	cgroup_fd = open(args.cgroup_path, O_RDONLY);
	if (cgroup_fd < 0) {
		perror("Failed to open cgroup path");
		return 1;
	}

	// Extract cgroup name from path
	char cgroup_name[256] = {0};
	const char *last_slash = strrchr(args.cgroup_path, '/');
	if (last_slash) {
		strncpy(cgroup_name, last_slash + 1, sizeof(cgroup_name) - 1);
	} else {
		strncpy(cgroup_name, args.cgroup_path, sizeof(cgroup_name) - 1);
	}

	// Prepare map paths
	char map_dir[512];
	snprintf(map_dir, sizeof(map_dir), "/sys/fs/bpf/cache_ext/%s", cgroup_name);
	
	char unified_metadata_path[512];
	snprintf(unified_metadata_path, sizeof(unified_metadata_path), "%s/unified_metadata_map", map_dir);
	
	char access_stats_path[512];
	snprintf(access_stats_path, sizeof(access_stats_path), "%s/access_stats_map", map_dir);
	
	char unified_ghost_path[512];
	snprintf(unified_ghost_path, sizeof(unified_ghost_path), "%s/unified_ghost_map", map_dir);

	// Open skel
	skel = cache_ext_mru_bpf__open();
	if (skel == NULL) {
		perror("Failed to open BPF skeleton");
		goto cleanup;
	}

	// Load programs
	
	// Try to reuse pinned unified maps
	int unified_metadata_fd = bpf_obj_get(unified_metadata_path);
	if (unified_metadata_fd >= 0) {
		int err = bpf_map__reuse_fd(skel->maps.unified_metadata_map, unified_metadata_fd);
		if (err) fprintf(stderr, "Failed to reuse unified_metadata_map: %d\n", err);
		close(unified_metadata_fd);
	}
	int access_stats_fd = bpf_obj_get(access_stats_path);
	if (access_stats_fd >= 0) {
		int err = bpf_map__reuse_fd(skel->maps.access_stats_map, access_stats_fd);
		if (err) fprintf(stderr, "Failed to reuse access_stats_map: %d\n", err);
		close(access_stats_fd);
	}
	int unified_ghost_fd = bpf_obj_get(unified_ghost_path);
	if (unified_ghost_fd >= 0) {
		int err = bpf_map__reuse_fd(skel->maps.unified_ghost_map, unified_ghost_fd);
		if (err) fprintf(stderr, "Failed to reuse unified_ghost_map: %d\n", err);
		close(unified_ghost_fd);
	}

ret = cache_ext_mru_bpf__load(skel);
	if (ret) {
		perror("Failed to load BPF skeleton");
		goto cleanup;
	}

	// Pin maps if not already pinned
	struct stat st;
	if (stat("/sys/fs/bpf/cache_ext", &st) != 0) {
		mkdir("/sys/fs/bpf/cache_ext", 0755);
	}
	if (stat(map_dir, &st) != 0) {
		mkdir(map_dir, 0755);
	}
	if (stat(unified_metadata_path, &st) != 0) {
		bpf_map__pin(skel->maps.unified_metadata_map, unified_metadata_path);
		bpf_map__pin(skel->maps.access_stats_map, access_stats_path);
		bpf_map__pin(skel->maps.unified_ghost_map, unified_ghost_path);
	}


	// Initialize watch_dir map
	ret = initialize_watch_dir_map(watch_dir_full_path, bpf_map__fd(skel->maps.inode_watchlist), true);
	if (ret) {
		perror("Failed to initialize watch_dir map");
		goto cleanup;
	}

	// Attach cache_ext_ops to the specific cgroup
	link = bpf_map__attach_cache_ext_ops(skel->maps.mru_ops, cgroup_fd);
	if (link == NULL) {
		perror("Failed to attach cache_ext_ops to cgroup");
		goto cleanup;
	}

	// Wait for keyboard input
	printf("Press any key to exit...\n");
	getchar();
	ret = 0;

cleanup:
	close(cgroup_fd);
	bpf_link__destroy(link);
	cache_ext_mru_bpf__destroy(skel);
	return ret;
}
