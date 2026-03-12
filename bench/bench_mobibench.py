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


def parse_mobibench_results(stdout: str) -> Dict:
    # Example output:
    # Total IO time : 10.000 sec (10000000 usec)
    # Total IO count : 252445 
    # Total Write: 123456 bytes, Read: 654321 bytes
    
    results = {}
    
    io_time_pattern = r"Total IO time : (\d+\.\d+) sec"
    io_count_pattern = r"Total IO count : (\d+)"
    write_bytes_pattern = r"Total Write: (\d+) bytes"
    read_bytes_pattern = r"Total Read: (\d+) bytes"
    
    # [TIME] :       1 sec 222901us.  878028413 B/sec,        857449.62 KB/sec,       837.35 MB/sec.
    time_pattern = r"\[TIME\] :\s+(\d+) sec (\d+)us\.\s+([\d\.]+) B/sec,\s+([\d\.]+) KB/sec,\s+([\d\.]+) MB/sec\."
    
    # Pattern for DB execution
    # [TIME] :       0 sec 017580us. 	568.83 Transactions/sec
    db_time_pattern = r"\[TIME\] :\s+(\d+) sec (\d+)us\.\s+([\d\.]+) Transactions/sec"
    
    # [CPU] : Active,Idle,IoWait : 15.66 74.10 10.24
    cpu_pattern = r"\[CPU\] : Active,Idle,IoWait : (\d+\.\d+) (\d+\.\d+) (\d+\.\d+)"
    
    cpu_match = re.search(cpu_pattern, stdout)
    if cpu_match:
        results["cpu_active"] = float(cpu_match.group(1))
        results["cpu_idle"] = float(cpu_match.group(2))
        results["cpu_iowait"] = float(cpu_match.group(3))
        
    time_match = re.search(time_pattern, stdout)
    if time_match:
        sec = int(time_match.group(1))
        usec = int(time_match.group(2))
        results["total_io_time_sec"] = sec + usec / 1000000.0
        
        results["total_throughput_b_s"] = float(time_match.group(3))
        results["total_throughput_kb_s"] = float(time_match.group(4))
        results["total_throughput_mb_s"] = float(time_match.group(5))
        
        results["write_throughput_mb_s"] = results["total_throughput_mb_s"]
        results["read_throughput_mb_s"] = results["total_throughput_mb_s"] 
        results["score"] = results["total_throughput_mb_s"]

    db_time_match = re.search(db_time_pattern, stdout)
    if db_time_match:
        sec = int(db_time_match.group(1))
        usec = int(db_time_match.group(2))
        results["total_io_time_sec"] = sec + usec / 1000000.0
        
        results["tps"] = float(db_time_match.group(3))
        results["score"] = results["tps"]
        
        if results["tps"] > 0:
            results["latency_us"] = 1000000.0 / results["tps"]
            results["latency_ms"] = 1000.0 / results["tps"]
    
    io_time = re.search(io_time_pattern, stdout)
    if io_time:
        results["total_io_time_sec"] = float(io_time.group(1))
        
    io_count = re.search(io_count_pattern, stdout)
    if io_count:
        results["total_io_count"] = int(io_count.group(1))
        
    write_bytes = re.search(write_bytes_pattern, stdout)
    if write_bytes:
        results["total_write_bytes"] = int(write_bytes.group(1))
        
    read_bytes = re.search(read_bytes_pattern, stdout)
    if read_bytes:
        results["total_read_bytes"] = int(read_bytes.group(1))
        
    if "total_io_time_sec" in results and "total_io_count" in results:
        if results["total_io_time_sec"] > 0:
            results["iops"] = results["total_io_count"] / results["total_io_time_sec"]
            
    if "total_io_time_sec" in results:
        if results["total_io_time_sec"] > 0:
            if "total_write_bytes" in results:
                results["write_throughput_mb_s"] = (results["total_write_bytes"] / 1024 / 1024) / results["total_io_time_sec"]
            if "total_read_bytes" in results:
                results["read_throughput_mb_s"] = (results["total_read_bytes"] / 1024 / 1024) / results["total_io_time_sec"]
            if "total_write_bytes" in results and "total_read_bytes" in results:
                results["total_throughput_mb_s"] = ((results["total_write_bytes"] + results["total_read_bytes"]) / 1024 / 1024) / results["total_io_time_sec"]

    if not results:
         raise Exception("Could not parse results from stdout: \n" + stdout)
         
    return results


class MobibenchBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("mobibench_benchmark", benchresults_cls, cli_args)
        self.cache_ext_policy = CacheExtPolicy(
            DEFAULT_CACHE_EXT_CGROUP, self.args.policy_loader, self.args.test_dir
        )
        CLEANUP_TASKS.append(lambda: self.cache_ext_policy.stop() if self.cache_ext_policy.has_started else None)

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--mobibench-binary",
            type=str,
            default="mobibench",
            help="Specify the path to the mobibench binary",
        )
        parser.add_argument(
            "--test-dir",
            type=str,
            required=True,
            help="Directory where mobibench will create files",
        )
        parser.add_argument(
            "--policy-loader",
            type=str,
            required=True,
            help="Specify the path to the policy loader binary",
        )
        parser.add_argument(
            "--file-size-kb",
            type=int,
            default=1024,
            help="File size in KB (default: 1024)",
        )
        parser.add_argument(
            "--record-size-kb",
            type=int,
            default=4,
            help="Record size in KB (default: 4)",
        )
        parser.add_argument(
            "--access-mode",
            type=str,
            default="write",
            help="Access mode: write, rnd_write, read, rnd_read, append",
        )
        parser.add_argument(
            "--sync-mode",
            type=str,
            default="normal",
            help="Sync mode: normal, o_sync, fsync, o_direct, sync_direct, mmap, mmap_async, mmap_sync, fdatasync",
        )
        parser.add_argument(
            "--num-threads",
            type=int,
            default=1,
            help="Number of threads",
        )
        parser.add_argument(
            "--db-mode",
            type=str,
            default=None,
            help="DB mode: insert, update, delete (if set, enables DB test)",
        )
        parser.add_argument(
            "--db-transactions",
            type=int,
            default=10,
            help="Number of DB transactions",
        )
        parser.add_argument(
            "--sqlite-journal-mode",
            type=str,
            default="truncate",
            help="SQLite journal mode: delete, truncate, persist, wal, memory, off",
        )
        parser.add_argument(
            "--sqlite-sync-mode",
            type=str,
            default="full",
            help="SQLite sync mode: off, normal, full",
        )
        parser.add_argument(
            "--cgroup-size",
            type=str,
            default=str(4 * GiB),
            help="Cgroup memory limit in bytes",
        )
        parser.add_argument(
            "--cache-ext-only",
            action="store_true",
            default=False,
            help="Run only the cache_ext config. Helpful for running policies.",
        )
        parser.add_argument(
            "--prepare-once",
            action="store_true",
            default=False,
            help="If set, assume files are already prepared (not fully applicable to mobibench as it creates files on run, but maybe for dir creation)",
        )

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option("cgroup_size", [int(self.args.cgroup_size)], configs)
        
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

        new_configs = []
        for config in configs:
            if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
                policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
                config["policy_loader"] = policy_loader_name
            new_configs.append(config)
        configs = new_configs
        
        configs = add_config_option(
            "iteration", list(range(1, self.args.iterations + 1)), configs
        )
        return configs

    def benchmark_prepare(self, config):
        drop_page_cache()
        disable_swap()
        disable_smt()
        
        if not os.path.exists(self.args.test_dir):
            os.makedirs(self.args.test_dir)

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
        access_mode_map = {
            "write": 0,
            "rnd_write": 1,
            "read": 2,
            "rnd_read": 3,
            "append": 4
        }
        
        sync_mode_map = {
            "normal": 0,
            "o_sync": 1,
            "fsync": 2,
            "o_direct": 3,
            "sync_direct": 4,
            "mmap": 5,
            "mmap_async": 6,
            "mmap_sync": 7,
            "fdatasync": 8
        }
        
        db_mode_map = {
            "insert": 0,
            "update": 1,
            "delete": 2
        }
        
        journal_mode_map = {
            "delete": 0,
            "truncate": 1,
            "persist": 2,
            "wal": 3,
            "memory": 4,
            "off": 5
        }
        
        sqlite_sync_mode_map = {
            "off": 0,
            "normal": 1,
            "full": 2
        }

        cmd_args = [
            self.args.mobibench_binary,
            "-p", self.args.test_dir,
            "-f", str(self.args.file_size_kb),
            "-r", str(self.args.record_size_kb),
            "-t", str(self.args.num_threads),
            "-a", str(access_mode_map.get(self.args.access_mode, 0)),
            "-y", str(sync_mode_map.get(self.args.sync_mode, 0)),
        ]
        
        if self.args.db_mode:
             cmd_args.extend([
                 "-d", str(db_mode_map.get(self.args.db_mode, 0)),
                 "-n", str(self.args.db_transactions),
                 "-j", str(journal_mode_map.get(self.args.sqlite_journal_mode, 1)),
                 "-s", str(sqlite_sync_mode_map.get(self.args.sqlite_sync_mode, 2))
             ])

        cmd = [
            "sudo",
            "cgexec",
            "-g",
            "memory:%s" % config["cgroup_name"],
            "setarch",
            os.uname().machine,
            "-R",
            "sh", "-c",
            ' '.join(cmd_args)
        ]
        return cmd

    def after_benchmark(self, config):
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            if self.cache_ext_policy.has_started:
                self.cache_ext_policy.stop()
        
        sleep(2)
        enable_smt()

    def parse_results(self, stdout: str) -> BenchResults:
        results = parse_mobibench_results(stdout)
        return BenchResults(results)


def main():
    global log
    mobibench_bench = MobibenchBenchmark()
    
    if "/" in mobibench_bench.args.mobibench_binary and not os.path.exists(mobibench_bench.args.mobibench_binary):
        raise Exception(
            "mobibench binary not found: %s"
            % mobibench_bench.args.mobibench_binary
        )
        
    log.info("Mobibench test directory: %s", mobibench_bench.args.test_dir)
    
    mobibench_bench.benchmark()


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
