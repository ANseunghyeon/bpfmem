import argparse
import logging
import os
import subprocess
from typing import Dict, List

FXMARK_BIN_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../fxmark/bin"))

from bench_lib import *

log = logging.getLogger(__name__)
GiB = 2**30
CLEANUP_TASKS = []

class FxmarkBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("fxmark_benchmark", benchresults_cls, cli_args)
        self.cache_ext_policy = CacheExtPolicy(
            DEFAULT_CACHE_EXT_CGROUP, self.args.policy_loader, self.args.workload_dir
        )
        CLEANUP_TASKS.append(lambda: self.cleanup_policy())
        
        self.fxmark_bin = os.path.join(FXMARK_BIN_DIR, "fxmark")
        self.root_dir = self.args.workload_dir
        self.disk_path = os.path.join(os.path.dirname(self.root_dir), "disk.img")
        self.loop_dev = None

    def cleanup_policy(self):
        if self.cache_ext_policy.has_started:
            self.cache_ext_policy.stop()
        self.teardown_fs()

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--workload-dir",
            type=str,
            required=True,
            help="Specify the directory where the workload operates (mount point)",
        )
        parser.add_argument(
            "--policy-loader",
            type=str,
            required=True,
            help="Specify the path to the policy loader binary",
        )
        parser.add_argument(
            "--benchmark-type",
            type=str,
            default="MWCL",
            help="Fxmark benchmark type (e.g., MWCL, DWAL, filebench_varmail)",
        )
        parser.add_argument(
            "--duration",
            type=int,
            default=30,
            help="Duration of the benchmark in seconds",
        )
        parser.add_argument(
            "--cache-ext-only",
            action="store_true",
            default=False,
            help="Run only the cache_ext config. Helpful for running policies.",
        )
        parser.add_argument(
            "--fs-type",
            type=str,
            default="ext4",
            help="Filesystem type (ext4, xfs, etc.)",
        )

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option("cgroup_size", [768 * 1024 * 1024], configs)
        configs = add_config_option("benchmark_type", [self.args.benchmark_type], configs)
        configs = add_config_option("duration", [self.args.duration], configs)
        
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
            else:
                new_configs.append(config)
        
        configs = new_configs
        configs = add_config_option(
            "iteration", list(range(1, self.args.iterations + 1)), configs
        )
        return configs

    def setup_fs(self):
        if not os.path.exists(self.disk_path):
            run(["dd", "if=/dev/zero", f"of={self.disk_path}", "bs=4G", "count=8"])
        
        try:
            out = check_output(["sudo", "losetup", "-f", "--show", self.disk_path], encoding="utf-8").strip()
            self.loop_dev = out
        except subprocess.CalledProcessError:
            log.error("Failed to setup loop device")
            raise

        mkfs_cmd = f"mkfs.{self.args.fs_type}"
        force_flag = "-F" if self.args.fs_type.startswith("ext") else "-f"
        run(["sudo", mkfs_cmd, force_flag, self.loop_dev])

        if not os.path.exists(self.root_dir):
            os.makedirs(self.root_dir)
        
        run(["sudo", "mount", self.loop_dev, self.root_dir])
        run(["sudo", "chmod", "777", self.root_dir])

    def teardown_fs(self):
        if os.path.ismount(self.root_dir):
            run(["sudo", "umount", self.root_dir])
        
        if self.loop_dev:
            run(["sudo", "losetup", "-d", self.loop_dev])
            self.loop_dev = None
        
        if os.path.exists(self.disk_path):
            os.remove(self.disk_path)

    def benchmark_prepare(self, config):
        drop_page_cache()
        disable_swap()
        disable_smt()
        
        self.teardown_fs()
        self.setup_fs()

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
        bench_type = config["benchmark_type"]
        
        if bench_type.startswith("filebench_"):
            bin_path = os.path.join(FXMARK_BIN_DIR, "run-filebench.py")
            workload_name = bench_type[len("filebench_"):]
        elif bench_type.startswith("dbench_"):
            bin_path = os.path.join(FXMARK_BIN_DIR, "run-dbench.py")
            workload_name = bench_type[len("dbench_"):]
        else:
            bin_path = self.fxmark_bin
            workload_name = bench_type

        # Calculate ncore and nbg
        ncore = config["cpus"]
        nbg = 0
        if config["benchmark_type"].endswith("_bg"):
            nbg = 1 
        
        cmd = [
            "sudo",
            "cgexec",
            "-g",
            f"memory:{config['cgroup_name']}",
            bin_path,
            "--type", workload_name,
            "--ncore", str(ncore),
            "--nbg", str(nbg),
            "--duration", str(config["duration"]),
            "--root", self.root_dir,
            "--profbegin", "true",
            "--profend", "true",
            "--proflog", "/dev/null"
        ]
        
        if bin_path == self.fxmark_bin:
             cmd.extend(["--directio", "0"])

        return cmd

    def after_benchmark(self, config):
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            self.cache_ext_policy.stop()
        
        self.teardown_fs()
        sleep(2)
        enable_smt()

    def parse_results(self, stdout: str) -> BenchResults:
        results = {}
        results["raw_output"] = stdout
        
        lines = stdout.splitlines()
        for line in lines:
            parts = line.split()
            if len(parts) >= 4 and parts[0].isdigit() and parts[1].isdigit():
                try:
                    results["throughput"] = float(parts[3])
                    results["throughput_unit"] = "ops/sec" # Or MB/sec for dbench
                    if "MB/sec" in line: # Dbench output might be different in wrapper, but wrapper prints space separated
                         pass
                except ValueError:
                    pass
        
        return BenchResults(results)

def main():
    global log
    fxmark_bench = FxmarkBenchmark()
    
    # Check that workload dir exists (or parent)
    parent_dir = os.path.dirname(fxmark_bench.args.workload_dir)
    if not os.path.exists(parent_dir):
        os.makedirs(parent_dir)
        
    fxmark_bench.benchmark()

if __name__ == "__main__":
    try:
        logging.basicConfig(level=logging.INFO)
        main()
    except Exception as e:
        log.error("Error in main: %s", e)
        log.info("Cleaning up")
        for task in CLEANUP_TASKS:
            task()
        raise e
