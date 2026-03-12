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


def parse_sysbench_results(stdout: str) -> Dict:
    # Example output:
    # File operations:
    #     reads/s:                      11836.06
    #     writes/s:                     7890.71
    #     fsyncs/s:                     25232.12
    #
    # Throughput:
    #     read, MiB/s:                  184.94
    #     written, MiB/s:               123.29
    #
    # General statistics:
    #     total time:                          10.0006s
    #     total number of events:              252445
    #
    # Latency (ms):
    #          min:                                    0.00
    #          avg:                                    0.04
    #          max:                                    8.07
    #          95th percentile:                        0.11
    #          sum:                                 9885.55
    
    results = {}
    
    reads_s_pattern = r"reads/s:\s+(\d+\.\d+)"
    writes_s_pattern = r"writes/s:\s+(\d+\.\d+)"
    read_mib_pattern = r"read, MiB/s:\s+(\d+\.\d+)"
    written_mib_pattern = r"written, MiB/s:\s+(\d+\.\d+)"
    latency_avg_pattern = r"avg:\s+(\d+\.\d+)"
    latency_95_pattern = r"95th percentile:\s+(\d+\.\d+)"
    
    reads_s = re.search(reads_s_pattern, stdout)
    if reads_s:
        results["reads_per_sec"] = float(reads_s.group(1))
        
    writes_s = re.search(writes_s_pattern, stdout)
    if writes_s:
        results["writes_per_sec"] = float(writes_s.group(1))
        
    read_mib = re.search(read_mib_pattern, stdout)
    if read_mib:
        results["read_mib_per_sec"] = float(read_mib.group(1))
        
    written_mib = re.search(written_mib_pattern, stdout)
    if written_mib:
        results["written_mib_per_sec"] = float(written_mib.group(1))
        
    latency_section = stdout.split("Latency (ms):")
    if len(latency_section) > 1:
        lat_part = latency_section[1]
        avg_lat = re.search(latency_avg_pattern, lat_part)
        if avg_lat:
            results["latency_avg_ms"] = float(avg_lat.group(1))
            
        p95_lat = re.search(latency_95_pattern, lat_part)
        if p95_lat:
            results["latency_95th_ms"] = float(p95_lat.group(1))

    if "reads_per_sec" in results and "writes_per_sec" in results:
        results["throughput_ops"] = results["reads_per_sec"] + results["writes_per_sec"]
        results["throughput_avg"] = results["throughput_ops"]
    
    if "read_mib_per_sec" in results and "written_mib_per_sec" in results:
        results["bandwidth_mb"] = results["read_mib_per_sec"] + results["written_mib_per_sec"]
        results["bandwidth_avg"] = results["bandwidth_mb"]

    if "latency_avg_ms" in results:
        results["latency_avg"] = results["latency_avg_ms"] * 1000000
        results["latency_avg_us"] = results["latency_avg_ms"] * 1000
    
    if not results:
         raise Exception("Could not parse results from stdout: \n" + stdout)
         
    return results


class SysbenchBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("sysbench_benchmark", benchresults_cls, cli_args)
        self.cache_ext_policy = CacheExtPolicy(
            DEFAULT_CACHE_EXT_CGROUP, self.args.policy_loader, self.args.sysbench_test_dir
        )
        CLEANUP_TASKS.append(lambda: self.cache_ext_policy.stop())

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--sysbench-binary",
            type=str,
            default="sysbench",
            help="Specify the path to the sysbench binary",
        )
        parser.add_argument(
            "--sysbench-test-dir",
            type=str,
            required=True,
            help="Directory where sysbench will create files",
        )
        parser.add_argument(
            "--policy-loader",
            type=str,
            required=True,
            help="Specify the path to the policy loader binary",
        )
        parser.add_argument(
            "--file-total-size",
            type=str,
            default="1G",
            help="Total size of files (e.g., 1G, 100M)",
        )
        parser.add_argument(
            "--file-num",
            type=int,
            default=128,
            help="Number of files to create",
        )
        parser.add_argument(
            "--file-test-mode",
            type=str,
            default="rndrd",
            help="Test mode: seqwr, seqrewr, seqrd, rndrd, rndwr, rndrw",
        )
        parser.add_argument(
            "--file-io-mode",
            type=str,
            default="sync",
            help="File I/O mode: sync, async, mmap",
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
            help="Number of threads",
        )
        parser.add_argument(
            "--prepare-once",
            action="store_true",
            default=False,
            help="If set, assume files are already prepared and do not cleanup",
        )

        parser.add_argument(
            "--file-block-size",
            type=str,
            default="16K",
            help="Block size to use for file I/O (e.g., 4K, 16K, 1M)",
        )
        parser.add_argument(
            "--cgroup-size",
            type=str,
            default=str(4 * GiB),
            help="Cgroup memory limit in bytes",
        )

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option("runtime_seconds", [600], configs)
        cgroup_size = int(self.args.cgroup_size)
        configs = add_config_option("cgroup_size", [cgroup_size], configs)
        
        configs = add_config_option("file_block_size", [self.args.file_block_size], configs)
        
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
        file_test_modes = parse_strings_string(self.args.file_test_mode)
        new_configs = []
        for config in configs:
            for mode in file_test_modes:
                config_with_mode = config.copy()
                config_with_mode["file_test_mode"] = mode
                
                if config_with_mode["cgroup_name"] == DEFAULT_BASELINE_CGROUP:
                    for fadvise in fadvise_hints:
                        new_config = config_with_mode.copy()
                        new_config["fadvise"] = fadvise
                        new_configs.append(new_config)
                elif config_with_mode["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
                    policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
                    config_with_mode["policy_loader"] = policy_loader_name
                    new_configs.append(config_with_mode)
                else:
                    new_configs.append(config_with_mode)
        configs = new_configs
        configs = add_config_option(
            "iteration", list(range(1, self.args.iterations + 1)), configs
        )
        return configs

    def benchmark_prepare(self, config):
        drop_page_cache()
        disable_swap()
        disable_smt()
        
        if not os.path.exists(self.args.sysbench_test_dir):
            os.makedirs(self.args.sysbench_test_dir)

        if not self.args.prepare_once:
             sysbench_cmd = [
                self.args.sysbench_binary,
                "fileio",
                f"--file-total-size={self.args.file_total_size}",
                f"--file-num={self.args.file_num}",
                "prepare"
             ]
             cmd = [
                "sudo",
                "sh", "-c",
                f"cd {self.args.sysbench_test_dir} && {' '.join(sysbench_cmd)}"
             ]
             run(cmd)

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
        sysbench_cmd = [
            self.args.sysbench_binary,
            "fileio",
            f"--file-total-size={self.args.file_total_size}",
            f"--file-num={self.args.file_num}",
            f"--file-test-mode={config['file_test_mode']}",
            f"--file-io-mode={self.args.file_io_mode}",
            f"--file-block-size={config['file_block_size']}",
            f"--threads={self.args.num_threads}",
            f"--time={config['runtime_seconds']}",
            "run"
        ]
        
        cmd = [
            "sudo",
            "cgexec",
            "-g",
            "memory:%s" % config["cgroup_name"],
            "setarch",
            os.uname().machine,
            "-R",
            "sh", "-c",
            f"cd {self.args.sysbench_test_dir} && {' '.join(sysbench_cmd)}"
        ]
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
        
        if not self.args.prepare_once:
            sysbench_cmd = [
                self.args.sysbench_binary,
                "fileio",
                f"--file-total-size={self.args.file_total_size}",
                f"--file-num={self.args.file_num}",
                "cleanup"
            ]
            cmd = [
                "sudo",
                "sh", "-c",
                f"cd {self.args.sysbench_test_dir} && {' '.join(sysbench_cmd)}"
            ]
            run(cmd)

        sleep(2)
        enable_smt()

    def parse_results(self, stdout: str) -> BenchResults:
        results = parse_sysbench_results(stdout)
        return BenchResults(results)


def main():
    global log
    sysbench_bench = SysbenchBenchmark()
    
    if "/" in sysbench_bench.args.sysbench_binary and not os.path.exists(sysbench_bench.args.sysbench_binary):
        raise Exception(
            "sysbench binary not found: %s"
            % sysbench_bench.args.sysbench_binary
        )
        
    log.info("Sysbench test directory: %s", sysbench_bench.args.sysbench_test_dir)
    
    sysbench_bench.benchmark()


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
