import argparse
import logging
import os
import re
import shutil
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


class DBenchBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("dbench_benchmark", benchresults_cls, cli_args)
        self.cache_ext_policy = CacheExtPolicy(
            DEFAULT_CACHE_EXT_CGROUP, self.args.policy_loader, self.args.work_dir
        )
        CLEANUP_TASKS.append(lambda: self.cleanup())

    def cleanup(self):
        if self.cache_ext_policy.has_started:
            self.cache_ext_policy.stop()
        
        pass

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--dbench-dir",
            type=str,
            default="/usr/bin",
            help="Path to directory containing dbench executable",
        )
        parser.add_argument(
            "--clients",
            type=int,
            default=10,
            help="Number of clients to simulate",
        )
        parser.add_argument(
            "--duration",
            type=int,
            default=60,
            help="Duration of the benchmark in seconds",
        )
        parser.add_argument(
            "--loadfile",
            type=str,
            default="/usr/share/dbench/client.txt",
            help="Path to dbench loadfile (client.txt)",
        )
        parser.add_argument(
            "--work-dir",
            type=str,
            default="/mnt/nvme/dbench_data",
            help="Directory to run dbench in (where files are created)",
        )
        parser.add_argument(
            "--policy-loader",
            type=str,
            required=True,
            help="Specify the path to the policy loader binary",
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
            "--results-dir",
            type=str,
            default="./results",
            help="Directory to store benchmark CSV results",
        )
        parser.add_argument(
            "--cgroup-size",
            type=int,
            default=4 * GiB,
            help="Cgroup memory limit in bytes",
        )

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
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
        disable_swap()
        disable_smt()
        
        os.makedirs(self.args.work_dir, exist_ok=True)
        
        dest_loadfile = os.path.join(self.args.work_dir, "client.txt")
        if os.path.abspath(self.args.loadfile) != os.path.abspath(dest_loadfile):
             shutil.copy(self.args.loadfile, dest_loadfile)

        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            recreate_cache_ext_cgroup(limit_in_bytes=config["cgroup_size"])
            
            move_pid_to_cgroup(os.getpid(), config["cgroup_name"])

            policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
            if policy_loader_name == "cache_ext_s3fifo.out":
                self.cache_ext_policy.start(cgroup_size=config["cgroup_size"])
            else:
                self.cache_ext_policy.start()
        else:
            recreate_baseline_cgroup(limit_in_bytes=config["cgroup_size"])
            move_pid_to_cgroup(os.getpid(), config["cgroup_name"])

    def benchmark_cmd(self, config):
        os.makedirs(self.args.results_dir, exist_ok=True)
        
        dbench_bin = os.path.join(self.args.dbench_dir, "dbench")
        if not os.path.exists(dbench_bin):
            dbench_bin = "dbench"
            
        cmd = [
            dbench_bin,
            "-t", str(self.args.duration),
            "-c", os.path.join(self.args.work_dir, "client.txt"),
            "-D", self.args.work_dir,
            str(self.args.clients)
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
        
        move_pid_to_cgroup(os.getpid(), "/")

        try:
            for filename in os.listdir(self.args.work_dir):
                if filename.startswith("dbench_client"):
                    os.remove(os.path.join(self.args.work_dir, filename))
        except Exception as e:
            log.warning(f"Failed to cleanup dbench files: {e}")

        sleep(2)
        enable_smt()

    def parse_results(self, stdout: str) -> BenchResults:
        results = {}
        
        # Parse throughput
        # Example output:
        # Throughput 123.45 MB/sec
        
        match = re.search(r"Throughput\s+([\d\.]+)\s+MB/sec", stdout)
        if match:
            throughput = float(match.group(1))
            results["throughput_mb_s"] = throughput
            results["score"] = throughput
        else:
            log.warning("Could not parse throughput from dbench output")
            lines = stdout.strip().split('\n')
            if lines:
                last_line = lines[-1]
                parts = last_line.split()
                try:
                    val = float(parts[-1])
                    pass
                except ValueError:
                    pass

        return BenchResults(results)


def main():
    global log
    dbench_bench = DBenchBenchmark()
    dbench_bench.benchmark()


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
