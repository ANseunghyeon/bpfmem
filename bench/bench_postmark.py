import argparse
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


class PostmarkBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("postmark_benchmark", benchresults_cls, cli_args)
        self.cache_ext_policy = CacheExtPolicy(
            DEFAULT_CACHE_EXT_CGROUP, self.args.policy_loader, self.args.work_dir
        )
        CLEANUP_TASKS.append(lambda: self.cleanup())

    def cleanup(self):
        if self.cache_ext_policy.has_started:
            self.cache_ext_policy.stop()

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--postmark-bin",
            type=str,
            default="postmark",
            help="Path to postmark binary",
        )
        parser.add_argument(
            "--work-dir",
            type=str,
            required=True,
            help="Directory for Postmark to create files in",
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
        parser.add_argument(
            "--pm-files",
            type=int,
            default=100000,
            help="Number of files for Postmark",
        )
        parser.add_argument(
            "--pm-sizes",
            type=str,
            default="4096 102400",
            help="File size range (min max) in bytes",
        )
        parser.add_argument(
            "--pm-transactions",
            type=int,
            default=200000,
            help="Number of transactions for Postmark",
        )
        parser.add_argument(
            "--pm-subdirs",
            type=int,
            default=200,
            help="Number of subdirectories for Postmark",
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
        
        if os.path.exists(self.args.work_dir):
            run(["rm", "-rf", os.path.join(self.args.work_dir, "*")])
        else:
            os.makedirs(self.args.work_dir, exist_ok=True)

        config_content = f"set location {self.args.work_dir}\n"
        config_content += f"set size {self.args.pm_sizes}\n"
        config_content += f"set number {self.args.pm_files}\n"
        config_content += f"set transactions {self.args.pm_transactions}\n"
        config_content += f"set subdirectories {self.args.pm_subdirs}\n"
        config_content += "set read 4096\n"
        config_content += "set write 4096\n"
        config_content += "set buffering true\n"
        config_content += "run\n"
        config_content += "quit\n"
        self.pm_config_file = os.path.join(self.args.results_dir, f"postmark_config_{config['iteration']}.cfg")
        with open(self.pm_config_file, "w") as f:
            f.write(config_content)
        
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
        
        cmd = ["sh", "-c", f"{self.args.postmark_bin} < {self.pm_config_file}"]
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

        sleep(2)
        enable_smt()
        
        # Cleanup work dir to save space (optional, but good practice)
        # run(["rm", "-rf", os.path.join(self.args.work_dir, "*")])

    def parse_results(self, stdout: str) -> BenchResults:
        results = {}
        
        # Postmark output example:
        # Time:
        # 	1 seconds total
        # 	1 seconds of transactions (200 per second)
        #
        # Data:
        # 	779.00 kilobytes read (779.00 kilobytes per second)
        # 	1.47 megabytes written (1.47 megabytes per second)
        
        lines = stdout.strip().split('\n')
        for line in lines:
            # Parse TPS
            if "transactions" in line and "per second)" in line:
                # Example: "	1 seconds of transactions (200 per second)"
                match = re.search(r'\((\d+)\s+per second\)', line)
                if match:
                    try:
                        tps = float(match.group(1))
                        results["tps"] = tps
                        results["score"] = tps
                    except ValueError:
                        pass
            
            # Parse Read BW
            if "read (" in line and "per second)" in line:
                # Example: "	779.00 kilobytes read (779.00 kilobytes per second)"
                match = re.search(r'read \(([\d\.]+)\s+(\w+)\s+per second\)', line)
                if match:
                    try:
                        val = float(match.group(1))
                        unit = match.group(2).lower()
                        if "kilobyte" in unit:
                            val /= 1024.0
                        elif "megabyte" in unit:
                            pass # already in MB
                        elif "byte" in unit:
                            val /= (1024.0 * 1024.0)
                        elif "gigabyte" in unit:
                            val *= 1024.0
                        results["read_bw_mbps"] = val
                    except ValueError:
                        pass

            # Parse Write BW
            if "written (" in line and "per second)" in line:
                # Example: "	1.47 megabytes written (1.47 megabytes per second)"
                match = re.search(r'written \(([\d\.]+)\s+(\w+)\s+per second\)', line)
                if match:
                    try:
                        val = float(match.group(1))
                        unit = match.group(2).lower()
                        if "kilobyte" in unit:
                            val /= 1024.0
                        elif "megabyte" in unit:
                            pass # already in MB
                        elif "byte" in unit:
                            val /= (1024.0 * 1024.0)
                        elif "gigabyte" in unit:
                            val *= 1024.0
                        results["write_bw_mbps"] = val
                    except ValueError:
                        pass
        
        return BenchResults(results)


def main():
    global log
    bench = PostmarkBenchmark()
    bench.benchmark()


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
