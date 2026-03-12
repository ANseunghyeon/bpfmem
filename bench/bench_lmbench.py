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
    # cgroup v2 path
    cgroup_path = f"/sys/fs/cgroup/{cgroup}" if cgroup != "/" else "/sys/fs/cgroup"
    procs_file = os.path.join(cgroup_path, "cgroup.procs")
    
    log.info(f"Moving PID {pid} to cgroup {cgroup} ({procs_file})")
    cmd = ["sudo", "sh", "-c", f"echo {pid} > {procs_file}"]
    run(cmd)


class LMBenchBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("lmbench_benchmark", benchresults_cls, cli_args)
        self.cache_ext_policy = CacheExtPolicy(
            DEFAULT_CACHE_EXT_CGROUP, self.args.policy_loader, self.args.lmbench_dir
        )
        CLEANUP_TASKS.append(lambda: self.cleanup())

    def cleanup(self):
        if self.cache_ext_policy.has_started:
            self.cache_ext_policy.stop()

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--lmbench-dir",
            type=str,
            required=True,
            help="Path to LMbench directory",
        )
        parser.add_argument(
            "--test-name",
            type=str,
            default="lat_mmap",
            help="Name of the LMbench test to run (e.g., lat_mmap) or 'suite' for full suite",
        )
        parser.add_argument(
            "--test-args",
            type=str,
            default="",
            help="Arguments for the LMbench test",
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
            "--config-file",
            type=str,
            default=None,
            help="Path to LMbench config file (required if test-name is 'suite')",
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
        
        if self.args.test_name == "suite":
             script_path = os.path.join(self.args.lmbench_dir, "scripts", "lmbench")
             if not os.path.exists(script_path):
                 raise Exception(f"LMbench script not found at {script_path}")
             
             if not self.args.config_file:
                 raise Exception("Config file is required for running the suite")

             scripts_dir = os.path.dirname(script_path)
             config_abs_path = os.path.abspath(self.args.config_file)
             
             bin_dir = os.path.join(self.args.lmbench_dir, "bin", "x86_64-linux-gnu")
             cmd = ["sh", "-c", f"export PATH={bin_dir}:$PATH && cd {scripts_dir} && ./lmbench {config_abs_path} 2>&1"]
             return cmd

        test_bin = os.path.join(self.args.lmbench_dir, "bin", "x86_64-linux-gnu", self.args.test_name)
        if not os.path.exists(test_bin):
            test_bin = os.path.join(self.args.lmbench_dir, "bin", self.args.test_name)
            
        if not os.path.exists(test_bin):
             test_bin = self.args.test_name

        cmd = [test_bin] + self.args.test_args.split()
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

    def parse_results(self, stdout: str) -> BenchResults:
        results = {}
        
        if self.args.test_name == "suite":
             policy_name = "baseline"
             if self.args.cache_ext_only:
                 pass
             
             results["raw_output"] = stdout
             return BenchResults(results)

        lines = stdout.strip().split('\n')
        if not lines:
            return BenchResults(results)

        last_line = lines[-1].strip()
        
        parts = last_line.split()
        if len(parts) >= 2:
            try:    
                val = float(parts[-1])
                results["latency_us"] = val
                results["latency_avg"] = val # us
                results["score"] = val
                return BenchResults(results)
            except ValueError:
                pass
        
        try:
            val = float(last_line)
            results["latency_us"] = val
            results["latency_avg"] = val
            results["score"] = val
            return BenchResults(results)
        except ValueError:
            pass

        numbers = re.findall(r"[-+]?\d*\.\d+|\d+", stdout)
        if numbers:
            try:
                val = float(numbers[-1])
                results["latency_us"] = val
                results["latency_avg"] = val
                results["score"] = val
            except ValueError:
                pass
        
        return BenchResults(results)


def run_suite(args):
    os.makedirs(args.results_dir, exist_ok=True)
    
    policy_name = "baseline"
    if args.cache_ext_only:
        policy_name = os.path.basename(args.policy_loader).replace(".out", "")
    elif args.default_only:
        policy_name = "baseline"
        
    output_file = os.path.join(args.results_dir, f"lmbench_{policy_name}_custom.out")
    
    test_file = "/mnt/nvme/lmbench_data/testfile_8g"
    file_size_mb = 8192
    
    log.info(f"Running custom LMbench suite on {test_file} ({file_size_mb}MB)")
    
    results = []
    
    # 1. Write Bandwidth (lmdd)
    # Note: lmdd writes to the file. This prepares it.
    # log.info("Running lmdd (Write Bandwidth)...")
    # cmd = [
    #     os.path.join(args.lmbench_dir, "bin", "x86_64-linux-gnu", "lmdd"),
    #     f"label=Write {file_size_mb}MB: ",
    #     f"of={test_file}",
    #     f"move={file_size_mb}m",
    #     "fsync=1",
    #     "print=3"
    # ]
    # try:
    #     out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
    #     log.info(out)
    #     results.append(out)
    # except subprocess.CalledProcessError as e:
    #     log.error(f"lmdd failed: {e.output}")
    #     results.append(f"lmdd failed: {e.output}")

    # 2. Read Bandwidth (bw_file_rd)
    log.info("Running bw_file_rd (Read Bandwidth)...")
    cmd = [
        os.path.join(args.lmbench_dir, "bin", "x86_64-linux-gnu", "bw_file_rd"),
        f"{file_size_mb}M",
        "open2close",
        test_file
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        log.info(f"Read BW: {out.strip()}")
        results.append(f"Read BW: {out}")
    except subprocess.CalledProcessError as e:
        log.error(f"bw_file_rd failed: {e.output}")

    # 3. mmap Latency (lat_mmap)
    # log.info("Running lat_mmap (mmap Latency)...")
    # cmd = [
    #     os.path.join(args.lmbench_dir, "bin", "x86_64-linux-gnu", "lat_mmap"),
    #     "-P", "1", "-W", "0", "-N", "1",
    #     f"{file_size_mb}M",
    #     test_file
    # ]
    # try:
    #     out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
    #     log.info(f"mmap Latency: {out.strip()}")
    #     results.append(f"mmap Latency: {out}")
    # except subprocess.CalledProcessError as e:
    #     log.error(f"lat_mmap failed: {e.output}")

    # # 4. Page Fault Latency (lat_pagefault)
    # log.info("Running lat_pagefault (Page Fault Latency)...")
    # cmd = [
    #     os.path.join(args.lmbench_dir, "bin", "x86_64-linux-gnu", "lat_pagefault"),
    #     "-P", "1", "-W", "0", "-N", "1",
    #     test_file
    # ]
    # try:
    #     # This can take long, so we might want a timeout, but let's let it run
    #     out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
    #     log.info(f"Page Fault Latency: {out.strip()}")
    #     results.append(f"Page Fault Latency: {out}")
    # except subprocess.CalledProcessError as e:
    #     log.error(f"lat_pagefault failed: {e.output}")

    # Save results
    with open(output_file, "w") as f:
        f.write("\n".join(results))
    log.info(f"Saved suite results to {output_file}")


def main():
    global log
    lmbench_bench = LMBenchBenchmark()
    
    if not os.path.exists(lmbench_bench.args.lmbench_dir):
        log.warning("LMbench directory not found: %s", lmbench_bench.args.lmbench_dir)
        
    log.info("LMbench test: %s %s", lmbench_bench.args.test_name, lmbench_bench.args.test_args)
    
    if lmbench_bench.args.test_name == "suite":
        config = {
            "cgroup_name": DEFAULT_BASELINE_CGROUP if lmbench_bench.args.default_only else DEFAULT_CACHE_EXT_CGROUP,
            "cgroup_size": lmbench_bench.args.cgroup_size
        }
        
        if lmbench_bench.args.cache_ext_only:
             config["policy_loader"] = os.path.basename(lmbench_bench.cache_ext_policy.loader_path)

        try:
            lmbench_bench.benchmark_prepare(config)
            run_suite(lmbench_bench.args)
        finally:
            lmbench_bench.after_benchmark(config)
            
    else:
        lmbench_bench.benchmark()


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
