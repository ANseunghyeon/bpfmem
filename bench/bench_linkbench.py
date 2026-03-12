import argparse
import csv
import logging
import os
import re
import subprocess
from time import sleep
from typing import Dict, List

from bench_lib import *

log = logging.getLogger(__name__)
GiB = 2**30
CLEANUP_TASKS = []


def move_pid_to_cgroup(pid: int, cgroup: str):
    cgroup_path = f"/sys/fs/cgroup/{cgroup}" if cgroup != "/" else "/sys/fs/cgroup"
    procs_file = os.path.join(cgroup_path, "cgroup.procs")
    
    log.info(f"Moving PID {pid} to cgroup {cgroup} ({procs_file})")
    cmd = ["sudo", "sh", "-c", f"echo {pid} > {procs_file}"]
    run(cmd)


class LinkBenchBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("linkbench_benchmark", benchresults_cls, cli_args)
        self.cache_ext_policy = CacheExtPolicy(
            DEFAULT_CACHE_EXT_CGROUP, self.args.policy_loader, self.args.db_data_dir
        )
        CLEANUP_TASKS.append(lambda: self.cleanup())

    def cleanup(self):
        if self.cache_ext_policy.has_started:
            self.cache_ext_policy.stop()
        if self.args.mysqld_pid:
            # Move mysqld back to root cgroup to avoid killing it when cgroup is deleted
            try:
                move_pid_to_cgroup(self.args.mysqld_pid, "/")
            except Exception as e:
                log.warning(f"Failed to move mysqld back to root cgroup: {e}")

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--linkbench-bin",
            type=str,
            default="./linkbench/bin/linkbench",
            help="Path to linkbench binary script",
        )
        parser.add_argument(
            "--config-file",
            type=str,
            required=True,
            help="Path to LinkBench config file",
        )
        parser.add_argument(
            "--policy-loader",
            type=str,
            required=True,
            help="Specify the path to the policy loader binary",
        )
        parser.add_argument(
            "--db-data-dir",
            type=str,
            required=True,
            help="Directory where DB data is stored (for cache_ext monitoring)",
        )
        parser.add_argument(
            "--mysqld-pid",
            type=int,
            default=None,
            help="PID of mysqld process to attach to cgroup",
        )
        parser.add_argument(
            "--requesters",
            type=int,
            default=10,
            help="Number of requester threads",
        )
        parser.add_argument(
            "--requests",
            type=int,
            default=100000,
            help="Number of requests per thread",
        )
        parser.add_argument(
            "--maxid1",
            type=int,
            default=None,
            help="Max ID1 (database size)",
        )
        parser.add_argument(
            "--cache-ext-only",
            action="store_true",
            default=False,
            help="Run only the cache_ext config.",
        )
        parser.add_argument(
            "--fadvise-hints",
            type=str,
            default="",
            help="Fadvise hints",
        )
        parser.add_argument(
            "--paper-config",
            action="store_true",
            default=False,
            help="Use standard paper configuration (10x RAM dataset, long runtime)",
        )
        parser.add_argument(
            "--cgroup-size",
            type=int,
            default=4 * GiB,
            help="Cgroup memory limit in bytes",
        )
        parser.add_argument(
            "--results-dir",
            type=str,
            default="./results",
            help="Directory to store benchmark CSV results",
        )

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        if self.args.paper_config:
            configs = add_config_option("runtime_seconds", [3600], configs)
        else:
            configs = add_config_option("runtime_seconds", [600], configs)
            
        configs = add_config_option("cgroup_size", [self.args.cgroup_size], configs)
        
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
        drop_page_cache()

        log.info("Restarting MySQL to flush InnoDB Buffer Pool...")
        subprocess.run(["sudo", "systemctl", "restart", "mysql"], check=True)
        sleep(5)
        try:
            pid_str = subprocess.check_output(["pgrep", "-x", "mysqld"]).decode().strip()
            self.args.mysqld_pid = int(pid_str.split('\n')[0])
            log.info(f"New mysqld PID: {self.args.mysqld_pid}")
        except subprocess.CalledProcessError:
            log.error("Failed to find mysqld PID after restart!")

        disable_swap()
        disable_smt()
        
        if self.args.mysqld_pid:
            move_pid_to_cgroup(self.args.mysqld_pid, "/")
            
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            recreate_cache_ext_cgroup(limit_in_bytes=config["cgroup_size"])
            
            if self.args.mysqld_pid:
                move_pid_to_cgroup(self.args.mysqld_pid, config["cgroup_name"])

            policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
            if policy_loader_name == "cache_ext_s3fifo.out":
                self.cache_ext_policy.start(cgroup_size=config["cgroup_size"])
            else:
                self.cache_ext_policy.start()
        else:
            recreate_baseline_cgroup(limit_in_bytes=config["cgroup_size"])
            if self.args.mysqld_pid:
                move_pid_to_cgroup(self.args.mysqld_pid, config["cgroup_name"])

    def benchmark_cmd(self, config):
        os.makedirs(self.args.results_dir, exist_ok=True)
        
        iteration = config.get("iteration", 1)
        cgroup = config.get("cgroup_name", "default")
        self.stats_csv_file = os.path.join(
            self.args.results_dir, 
            f"linkbench_stats_{cgroup}_iter{iteration}.csv"
        )
        
        cmd = [
            self.args.linkbench_bin,
            "-c", self.args.config_file,
            "-r",
            "-D", f"requesters={self.args.requesters}",
            "-D", f"requests={self.args.requests}",
            "-D", f"maxtime={config['runtime_seconds']}",
            "-D", "displayfreq=10",
            "-D", "progressfreq=10",
            "-csvstats", self.stats_csv_file  
        ]
        
        if self.args.maxid1:
            cmd.extend(["-D", f"maxid1={self.args.maxid1}"])
            
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
        
        if self.args.mysqld_pid:
            move_pid_to_cgroup(self.args.mysqld_pid, "/")

        sleep(2)
        enable_smt()

    def parse_results(self, stdout: str) -> BenchResults:
        results = {}
        
        throughput_pattern = r"(?:Requests|Links)/second = (\d+)"
        throughput_matches = re.findall(throughput_pattern, stdout)
        if throughput_matches:
            results["throughput_ops"] = int(throughput_matches[-1])
            results["throughput_avg"] = float(results["throughput_ops"])
        else:
            throughput_pattern_new = r"at (\d+\.\d+) ops/sec"
            throughput_matches = re.findall(throughput_pattern_new, stdout)
            if throughput_matches:
                results["throughput_ops"] = float(throughput_matches[-1])
                results["throughput_avg"] = results["throughput_ops"]

        if "throughput_ops" not in results:
             log.warning("Could not parse throughput from LinkBench stdout")

        if hasattr(self, 'stats_csv_file') and os.path.exists(self.stats_csv_file):
            try:
                with open(self.stats_csv_file, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        op_name = row.get('op', '').strip()
                        if op_name in ('GET_LINKS_LIST', 'LOAD_LINKS_BULK'):
                            val_mean = float(row.get('mean', 0))
                            results["latency_avg_us"] = val_mean
                            results["latency_avg_ms"] = val_mean / 1000.0
                            results["latency_avg"] = val_mean * 1000.0 # ns

                            if 'p99' in row:
                                results["latency_p99_us"] = float(row['p99'])
                                results["latency_p99_ms"] = float(row['p99']) / 1000.0
                            break
                log.info(f"Successfully parsed latency metrics from {self.stats_csv_file}")
            except Exception as e:
                log.error(f"Failed to parse CSV stats from {self.stats_csv_file}: {e}")
        else:
            log.warning("CSV stats file not found, latency metrics will be missing.")

        return BenchResults(results)


def main():
    global log
    linkbench_bench = LinkBenchBenchmark()
    
    if not os.path.exists(linkbench_bench.args.linkbench_bin):
        raise Exception(
            "LinkBench binary not found: %s"
            % linkbench_bench.args.linkbench_bin
        )
    
    if not os.path.exists(linkbench_bench.args.config_file):
        raise Exception(
            "Config file not found: %s"
            % linkbench_bench.args.config_file
        )
        
    log.info("LinkBench config: %s", linkbench_bench.args.config_file)
    if linkbench_bench.args.mysqld_pid:
        log.info("Managing mysqld PID: %d", linkbench_bench.args.mysqld_pid)
    
    linkbench_bench.benchmark()


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