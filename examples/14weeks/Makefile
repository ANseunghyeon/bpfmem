# =============================================================================
# Makefile for 14weeks experiment
# =============================================================================

CC ?= gcc
CFLAGS := -O2 -g -Wall -Wextra -pthread

# Paths
ROOT := ../..
POLICIES_DIR := $(ROOT)/policies
IRP_DIR := $(ROOT)/IRP
LIBBPF_DIR := $(ROOT)/linux/tools/lib/bpf

# Includes
INCS := -I$(POLICIES_DIR) -I$(IRP_DIR) -I$(LIBBPF_DIR)

# Libraries (order matters for static linking)
LIBS := $(POLICIES_DIR)/libcacheext.a $(LIBBPF_DIR)/libbpf.a -lelf -lz -lpthread

# Targets
WORKLOAD := multi_phase_workload
CONTROLLER := dynamic_policy_controller

# Default target
all: $(WORKLOAD) $(CONTROLLER)

# Multi-phase workload (standalone, no BPF dependency)
$(WORKLOAD): multi_phase_workload.c
	$(CC) $(CFLAGS) -o $@ $< -lpthread -lrt

# Dynamic policy controller (depends on mem_monitor and cacheext)
$(CONTROLLER): dynamic_policy_controller.c $(POLICIES_DIR)/libcacheext.a $(IRP_DIR)/mem_monitor.skel.h
	$(CC) $(CFLAGS) $(INCS) -o $@ $< $(LIBS)

# Build dependencies if not present
$(POLICIES_DIR)/libcacheext.a:
	$(MAKE) -C $(POLICIES_DIR) libcacheext.a

$(IRP_DIR)/mem_monitor.skel.h:
	$(MAKE) -C $(IRP_DIR) mem_monitor.skel.h

# Quick test
test: $(WORKLOAD)
	./$(WORKLOAD) --size 32 --working-set 8 --iterations 1 --output-dir /tmp/14weeks_test

# Run full experiment (requires root)
experiment: all
	sudo ./run_experiment.sh

# Clean
clean:
	rm -f $(WORKLOAD) $(CONTROLLER)
	rm -rf /tmp/14weeks_*

# Help
help:
	@echo "14weeks Experiment Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all         - Build workload and controller (default)"
	@echo "  workload    - Build only the multi-phase workload"
	@echo "  controller  - Build only the dynamic policy controller"
	@echo "  test        - Quick test run of workload"
	@echo "  experiment  - Run full experiment (requires root)"
	@echo "  clean       - Remove built files"
	@echo ""
	@echo "Run 'sudo ./run_experiment.sh --help' for experiment options"

.PHONY: all test experiment clean help

# Aliases
workload: $(WORKLOAD)
controller: $(CONTROLLER)

