// Minimal API for switching cache extension policies from user programs.
#ifndef CACHEEXT_API_H
#define CACHEEXT_API_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	CACHEEXT_POLICY_NONE = 0,
	CACHEEXT_POLICY_FIFO,
	CACHEEXT_POLICY_MRU,
	CACHEEXT_POLICY_MGLRU,
	CACHEEXT_POLICY_LHD,
	CACHEEXT_POLICY_S3FIFO,
	CACHEEXT_POLICY_SAMPLING,
	CACHEEXT_POLICY_GET_SCAN,
} cacheext_policy_t;

// Helper: parse policy name string to enum
bool cacheext_policy_from_string(const char *name, cacheext_policy_t *out);

// Threaded manager API
// cache_ext(): change kernel policy to the requested one (synchronous).
//  - policy_name: e.g., "s3fifo","fifo","mru","mglru","lhd","sampling","get_scan","none"
//  - Returns 0 on success.
int cache_ext(const char *policy_name,
	      const char *cgroup_path,
	      const char *watch_dir,
	      unsigned long cgroup_size_bytes);

// Shutdown background manager thread and detach any active policy.
int cache_ext_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* CACHEEXT_API_H */
