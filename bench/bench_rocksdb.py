import argparse
import logging
import os
import re
from time import sleep
from typing import Dict, List

from bench_lib import *


log = logging.getLogger(__name__)
GiB = 2**30
CLEANUP_TASKS = []


def reset_database(db_dir: str, temp_db_dir: str):
    if os.path.exists(temp_db_dir):
        run(["rm", "-rf", temp_db_dir])
    
    os.makedirs(os.path.dirname(temp_db_dir), exist_ok=True)
    
    if db_dir.endswith("/"):
        db_dir = db_dir[:-1]
        
    run(["cp", "-r", "--reflink=auto", db_dir, temp_db_dir])


def parse_rocksdb_bench_results(stdout: str) -> Dict:
    # Example output:
    # fillseq      :       0.445 micros/op 2245628 ops/sec;   24.7 MB/s
    # readrandom   :       2.387 micros/op 418932 ops/sec;   46.2 MB/s (359999 of 359999 found)
    results = {}
    for line in stdout.splitlines():
        line = line.strip()
        # Parse throughput and latency
        # <benchmark> : <latency> micros/op <throughput> ops/sec; <bandwidth> MB/s
        # Example: readrandom   :       0.227 micros/op 4407190 ops/sec 60.000 seconds 264432999 operations; (0 of 264432999 found)
        pattern = r"(\w+)\s+:\s+(\d+\.\d+) micros/op (\d+) ops/sec"
        matches = re.findall(pattern, line)
        if matches:
            match = matches[0]
            bench_name = match[0]
            latency_micros = float(match[1])
            throughput_ops = int(match[2])
            
            # Try to find bandwidth if available
            bandwidth_mb = 0.0
            bw_pattern = r"(\d+\.\d+) MB/s"
            bw_matches = re.findall(bw_pattern, line)
            if bw_matches:
                bandwidth_mb = float(bw_matches[0])
            
            results[f"{bench_name}_latency_avg_us"] = latency_micros
            results[f"{bench_name}_throughput_ops"] = throughput_ops
            results[f"{bench_name}_bandwidth_mb"] = bandwidth_mb
            
            results["throughput_avg"] = float(throughput_ops)
            results["latency_avg"] = latency_micros * 1000
            results["bandwidth_avg"] = bandwidth_mb

    if "throughput_avg" not in results:
        pass
        
    if not results:
         raise Exception("Could not parse results from stdout: \n" + stdout)
         
    return results


class RocksDBBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("rocksdb_benchmark", benchresults_cls, cli_args)
        if self.args.rocksdb_temp_db is None:
            self.args.rocksdb_temp_db = self.args.rocksdb_db + "_temp"
        self.cache_ext_policy = CacheExtPolicy(
            DEFAULT_CACHE_EXT_CGROUP, self.args.policy_loader, self.args.rocksdb_temp_db
        )
        CLEANUP_TASKS.append(lambda: self.cache_ext_policy.stop())

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--rocksdb-db",
            type=str,
            required=True,
            help="Specify the directory to watch for cache_ext (source DB)",
        )
        parser.add_argument(
            "--rocksdb-temp-db",
            type=str,
            default=None,
            help="Specify the temporary directory for RocksDB benchmarking. Default is <rocksdb-db>_temp",
        )
        parser.add_argument(
            "--policy-loader",
            type=str,
            required=True,
            help="Specify the path to the policy loader binary",
        )
        parser.add_argument(
            "--db-bench-binary",
            type=str,
            required=True,
            help="Specify the path to the db_bench binary",
        )
        parser.add_argument(
            "--benchmark",
            type=str,
            default="readrandom",
            help="Specify the benchmark to run, e.g., 'readrandom'",
        )
        parser.add_argument(
            "--fadvise-hints",
            type=str,
            default="",
            help="Specify the fadvise hints to use for the baseline cgroup",
        )
        parser.add_argument(
            "--cache-ext-only",
            action="store_true",
            default=False,
            help="Run only the cache_ext config. Helpful for running policies.",
        )
        parser.add_argument(
            "--num-threads",
            type=int,
            default=1,
            help="Number of threads for db_bench",
        )
        parser.add_argument(
            "--value-size",
            type=int,
            default=100,
            help="Size of each value",
        )
        # parser.add_argument(
        #     "--cache-size",
        #     type=int,
        #     default=1048576, # 1MB default cache size in db_bench
        #     help="Cache size in bytes",
        # )
        parser.add_argument(
            "--compression-type",
            type=str,
            default="none",
            help="Compression type (none, snappy, zlib, bzip2, lz4, lz4hc, xpress, zstd)",
        )
        parser.add_argument(
            "--bloom-bits",
            type=int,
            default=10,
            help="Bloom filter bits per key",
        )
        parser.add_argument(
            "--workload-suite",
            type=str,
            default="default",
            choices=["default", "lsm-paper", "kv-paper"],
            help="Predefined workload suite to run",
        )
        parser.add_argument(
            "--use-direct-reads",
            action="store_true",
            default=False,
            help="Use direct I/O for reads",
        )
        parser.add_argument(
            "--num",
            type=int,
            default=None,
            help="Number of keys (passed to db_bench)",
        )

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option("runtime_seconds", [600], configs)
        configs = add_config_option("cgroup_size", [4 * GiB], configs)
        
        if self.args.workload_suite == "lsm-paper":
            benchmarks = ["fillrandom", "readrandom", "readwhilewriting", "seekrandom"]
        elif self.args.workload_suite == "kv-paper":
            benchmarks = ["fillseq", "readrandom", "updaterandom"]
        else:
            benchmarks = parse_strings_string(self.args.benchmark)
            
        configs = add_config_option(
            "benchmark", benchmarks, configs
        )
        
        if self.args.default_only:
            configs = add_config_option(
                "cgroup_name", [DEFAULT_BASELINE_CGROUP], configs
            )
        elif self.args.cache_ext_only:
            configs = add_config_option(
                "cgroup_name", [DEFAULT_CACHE_EXT_CGROUP], configs
            )
        else:
            configs = add_config_option(
                "cgroup_name",
                [DEFAULT_BASELINE_CGROUP, DEFAULT_CACHE_EXT_CGROUP],
                configs,
            )

        fadvise_hints = parse_strings_string(self.args.fadvise_hints)
        new_configs = []
        for config in configs:
            if config["cgroup_name"] == DEFAULT_BASELINE_CGROUP:
                for fadvise in fadvise_hints:
                    new_config = config.copy()
                    new_config["fadvise"] = fadvise
                    new_configs.append(new_config)
            elif config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
                policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
                config["policy_loader"] = policy_loader_name
                new_configs.append(config)
            else:
                new_configs.append(config)
        configs = new_configs
        configs = add_config_option(
            "iteration", list(range(1, self.args.iterations + 1)), configs
        )
        return configs

    def benchmark_prepare(self, config):
        reset_database(self.args.rocksdb_db, self.args.rocksdb_temp_db)
        drop_page_cache()
        disable_swap()
        disable_smt()
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            recreate_cache_ext_cgroup(limit_in_bytes=config["cgroup_size"])

            policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
            if policy_loader_name == "cache_ext_s3fifo.out":
                self.cache_ext_policy.start(cgroup_size=config["cgroup_size"])
            else:
                self.cache_ext_policy.start()
        else:
            recreate_baseline_cgroup(limit_in_bytes=config["cgroup_size"])

    def benchmark_cmd(self, config):
        cmd = [
            "sudo",
            "cgexec",
            "-g",
            "memory:%s" % config["cgroup_name"],
            "setarch",
            os.uname().machine,
            "-R",
            self.args.db_bench_binary,
            f"--db={self.args.rocksdb_temp_db}",
            f"--benchmarks={config['benchmark']}",
            f"--use_existing_db={0 if str(config['benchmark']).startswith('fill') else 1}",
            f"--threads={self.args.num_threads}",
            f"--value_size={self.args.value_size}",
            # f"--cache_size={self.args.cache_size}",
            f"--duration={config['runtime_seconds']}",
            "--statistics=1",
            "--histogram=1",
            f"--compression_type={self.args.compression_type}",
            f"--bloom_bits={self.args.bloom_bits}",
        ]
        if self.args.use_direct_reads:
            cmd.append("--use_direct_reads=1")
            cmd.append("--use_direct_io_for_flush_and_compaction=1")
        
        if self.args.num is not None:
            cmd.append(f"--num={self.args.num}")
        return cmd

    def cmd_extra_envs(self, config):
        extra_envs = {}
        if config["cgroup_name"] == DEFAULT_BASELINE_CGROUP and config["fadvise"] != "":
            extra_envs["ENABLE_SCAN_FADVISE"] = config["fadvise"]
        return extra_envs

    def after_benchmark(self, config):
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            if self.cache_ext_policy.has_started:
                self.cache_ext_policy.stop()
        sleep(2)
        enable_smt()

    def parse_results(self, stdout: str) -> BenchResults:
        results = parse_rocksdb_bench_results(stdout)
        return BenchResults(results)


def main():
    global log
    rocksdb_bench = RocksDBBenchmark()
    
    if not os.path.exists(rocksdb_bench.args.rocksdb_db):
        raise Exception(
            "RocksDB DB directory not found: %s" % rocksdb_bench.args.rocksdb_db
        )
    if not os.path.exists(rocksdb_bench.args.db_bench_binary):
        raise Exception(
            "db_bench binary not found: %s"
            % rocksdb_bench.args.db_bench_binary
        )
        
    log.info("RocksDB DB directory: %s", rocksdb_bench.args.rocksdb_db)
    log.info("RocksDB temp DB directory: %s", rocksdb_bench.args.rocksdb_temp_db)
    rocksdb_bench.benchmark()


if __name__ == "__main__":
    try:
        logging.basicConfig(level=logging.INFO)
        main()
    except Exception as e:
        log.error("Error in main: %s", e)
        log.info("Cleaning up")
        for task in CLEANUP_TASKS:
            task()
        log.error("Re-raising exception")
        raise e
