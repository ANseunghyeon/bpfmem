# examples/Makefile
CC = gcc
CFLAGS = -O2 -Wall -g

POLICY_DIR = ../policies
POLICY_INCLUDE = -I$(POLICY_DIR)

# 커스텀 libbpf 경로 (cache_ext 커널용)
LIBBPF_DIR = /usr/local/lib64
POLICY_LIB = -L$(POLICY_DIR) -L$(LIBBPF_DIR) -Wl,-rpath,$(LIBBPF_DIR) \
             -lcacheext -lbpf -lelf -lz -lpthread

all: test_workload test_cacheext_api

test_workload: test_workload.c
	$(CC) $(CFLAGS) -o $@ $<

test_cacheext_api: test_cacheext_api.c $(POLICY_DIR)/libcacheext.a
	$(CC) $(CFLAGS) $(POLICY_INCLUDE) -o $@ $< $(POLICY_LIB)

$(POLICY_DIR)/libcacheext.a:
	@echo "libcacheext.a가 없습니다. policies 디렉토리에서 make를 실행하세요."
	@echo "  cd $(POLICY_DIR) && make"
	@exit 1

clean:
	rm -f test_workload test_cacheext_api

.PHONY: all clean
