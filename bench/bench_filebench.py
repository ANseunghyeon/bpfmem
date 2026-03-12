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


def parse_filebench_results(stdout: str) -> Dict:
    # Example output:
    # IO Summary: 3452 ops 34.5 ops/s 1.2mb/s 234us cpu/op 4.5ms latency
    results = {}
    for line in stdout.splitlines():
        line = line.strip()
        if "IO Summary:" in line:
            # Parse throughput and latency
            # IO Summary: <ops> ops <ops/s> ops/s <mb/s>mb/s <cpu/op>us cpu/op <latency>ms latency
            # Example: 62.250: IO Summary: 9697416 ops 161542.207 ops/s 14686/29372 rd/wr 3857.3mb/s 0.065ms/op
            pattern = r"IO Summary: (\d+) ops (\d+\.\d+) ops/s .* (\d+\.\d+)mb/s (\d+\.\d+)ms/op"
            matches = re.findall(pattern, line)
            if matches:
                match = matches[0]
                results["ops"] = int(match[0])
                results["ops_per_sec"] = float(match[1])
                results["mb_per_sec"] = float(match[2])
                results["latency_ms"] = float(match[3])
                results["throughput_avg"] = results["ops_per_sec"]
                results["latency_avg"] = results["latency_ms"] * 1000000
                results["latency_avg_ns"] = results["latency_ms"] * 1000000
            else:   
                 pass
    
    if "ops_per_sec" not in results:
        raise Exception("Could not parse results from stdout: \n" + stdout)
    return results


class FilebenchBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("filebench_benchmark", benchresults_cls, cli_args)
        self.cache_ext_policy = CacheExtPolicy(
            DEFAULT_CACHE_EXT_CGROUP, self.args.policy_loader, self.args.workload_dir
        )
        CLEANUP_TASKS.append(lambda: self.cleanup_policy())

    def cleanup_policy(self):
        if self.cache_ext_policy.has_started:
            self.cache_ext_policy.stop()

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--workload-file",
            type=str,
            required=True,
            help="Specify the path to the filebench workload file (.f)",
        )
        parser.add_argument(
            "--workload-dir",
            type=str,
            required=True,
            help="Specify the directory where the workload operates (for cache_ext monitoring)",
        )
        parser.add_argument(
            "--policy-loader",
            type=str,
            required=True,
            help="Specify the path to the policy loader binary",
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
            "--filebench-binary",
            type=str,
            default="filebench",
            help="Specify the path to the filebench binary",
        )
    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option("runtime_seconds", [600], configs)
        configs = add_config_option("cgroup_size", [4 * GiB], configs)
        
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

            policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
            if policy_loader_name == "cache_ext_s3fifo.out":
                self.cache_ext_policy.start(cgroup_size=config["cgroup_size"])
            else:
                self.cache_ext_policy.start()
        else:
            recreate_baseline_cgroup(limit_in_bytes=config["cgroup_size"])

    def benchmark_cmd(self, config):
        with open(self.args.workload_file, 'r') as f:
            content = f.read()
        
        lines = content.splitlines()
        new_lines = [line for line in lines if not line.strip().startswith('run')]
        new_lines.append(f"run {config['runtime_seconds']}")
        
        temp_workload_file = os.path.join("/tmp", os.path.basename(self.args.workload_file) + ".tmp")
        with open(temp_workload_file, 'w') as f:
            f.write('\n'.join(new_lines))
            
        cmd = [
            "sudo",
            "cgexec",
            "-g",
            "memory:%s" % config["cgroup_name"],
            "setarch",
            os.uname().machine,
            "-R",
            self.args.filebench_binary,
            "-f",
            temp_workload_file,
        ]
        return cmd

    def cmd_extra_envs(self, config):
        extra_envs = {}
        if config["cgroup_name"] == DEFAULT_BASELINE_CGROUP and config["fadvise"] != "":
            extra_envs["ENABLE_SCAN_FADVISE"] = config["fadvise"]
        return extra_envs

    def after_benchmark(self, config):
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            self.cache_ext_policy.stop()
        
        temp_workload_file = os.path.join("/tmp", os.path.basename(self.args.workload_file) + ".tmp")
        if os.path.exists(temp_workload_file):
            os.remove(temp_workload_file)
            
        sleep(2)
        enable_smt()

    def parse_results(self, stdout: str) -> BenchResults:
        results = parse_filebench_results(stdout)
        return BenchResults(results)


def main():
    global log
    filebench_bench = FilebenchBenchmark()
    
    if not os.path.exists(filebench_bench.args.workload_file):
        raise Exception(
            "Workload file not found: %s" % filebench_bench.args.workload_file
        )
    
    if not os.path.exists(filebench_bench.args.workload_dir):
        if not os.path.exists(filebench_bench.args.workload_dir):
             os.makedirs(filebench_bench.args.workload_dir)
        
    log.info("Workload file: %s", filebench_bench.args.workload_file)
    filebench_bench.benchmark()


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
