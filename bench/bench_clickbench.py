import argparse
import json
import logging
import os
import subprocess
import time
import sys
import re
from typing import Dict, List
from bench_lib import *

log = logging.getLogger(__name__)
GiB = 2**30
CLEANUP_TASKS = []

class ClickBenchBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("clickbench_benchmark", benchresults_cls, cli_args)
        self.cache_ext_policy = None
        self.server_process = None
        CLEANUP_TASKS.append(lambda: self.cleanup())

    def cleanup(self):
        if self.cache_ext_policy and self.cache_ext_policy.has_started:
            self.cache_ext_policy.stop()
        self.stop_server()

    def stop_server(self):
        if self.server_process:
            log.info("Stopping ClickHouse server...")
            self.server_process.terminate()
            try:
                self.server_process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.server_process.kill()
            self.server_process = None

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument("--clickhouse-bin", type=str, required=True, help="Path to clickhouse binary")
        parser.add_argument("--data-dir", type=str, required=True, help="Path to data directory")
        parser.add_argument("--config-file", type=str, required=True, help="Path to config.xml")
        parser.add_argument("--queries-file", type=str, required=True, help="Path to queries.sql")
        parser.add_argument("--policy-loader", type=str, required=True, help="Path to policy loader")
        parser.add_argument("--cache-ext-only", action="store_true", default=False, help="Run only cache_ext config")
        parser.add_argument("--fadvise-hints", type=str, default="", help="Fadvise hints")
        parser.add_argument("--results-dir", type=str, default="./results", help="Results directory")
        parser.add_argument("--cgroup-size", type=int, default=4 * GiB, help="Cgroup memory limit")

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option("cgroup_size", [self.args.cgroup_size], configs)
        if self.args.default_only:
            configs = add_config_option("cgroup_name", [DEFAULT_BASELINE_CGROUP], configs)
        elif self.args.cache_ext_only:
            configs = add_config_option("cgroup_name", [DEFAULT_CACHE_EXT_CGROUP], configs)
        else:
            configs = add_config_option("cgroup_name", [DEFAULT_BASELINE_CGROUP, DEFAULT_CACHE_EXT_CGROUP], configs)
        
        fadvise_hints = parse_strings_string(self.args.fadvise_hints)
        new_configs = []
        for config in configs:
            if config["cgroup_name"] == DEFAULT_BASELINE_CGROUP:
                for fadvise in fadvise_hints:
                    new_config = config.copy()
                    new_config["fadvise"] = fadvise
                    new_configs.append(new_config)
            elif config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
                policy_loader_name = os.path.basename(self.args.policy_loader)
                config["policy_loader"] = policy_loader_name
                new_configs.append(config)
            else:
                new_configs.append(config)
        configs = new_configs
        configs = add_config_option("iteration", list(range(1, self.args.iterations + 1)), configs)
        return configs

    def benchmark_prepare(self, config):
        drop_page_cache()
        disable_swap()
        disable_smt()
        
        self.cache_ext_policy = CacheExtPolicy(
            DEFAULT_CACHE_EXT_CGROUP, self.args.policy_loader, self.args.data_dir
        )

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
            sys.executable, os.path.abspath(__file__),
            "--run-internal",
            "--clickhouse-bin", self.args.clickhouse_bin,
            "--queries-file", self.args.queries_file,
            "--iterations", str(self.args.iterations),
        ]
        return cmd

    def before_benchmark(self, config):
        log.info("Starting ClickHouse server...")
        os.makedirs(self.args.data_dir, exist_ok=True)
        
        cgroup_path = f"memory:{config['cgroup_name']}"
        
        cmd = [
            "sudo", "cgexec", "-g", cgroup_path,
            self.args.clickhouse_bin, "server",
            "--config-file", self.args.config_file,
        ]
        
        self.server_log = open(os.path.join(self.args.results_dir, "server.log"), "w")
        self.server_err = open(os.path.join(self.args.results_dir, "server.err"), "w")

        self.server_process = subprocess.Popen(
            cmd,
            stdout=self.server_log,
            stderr=self.server_err,
            preexec_fn=os.setsid
        )
        
        log.info("Waiting for server to be ready...")
        time.sleep(5)
        
        retries = 30
        while retries > 0:
            try:
                subprocess.check_call([self.args.clickhouse_bin, "client", "--query", "SELECT 1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                break
            except subprocess.CalledProcessError:
                time.sleep(1)
                retries -= 1
        
        if retries == 0:
            if self.server_process.poll() is not None:
                log.error("Server process exited prematurely")
            raise Exception("Server failed to start")
        
        log.info("Server is ready.")

    def after_benchmark(self, config):
        self.stop_server()
        if hasattr(self, 'server_log'):
            self.server_log.close()
        if hasattr(self, 'server_err'):
            self.server_err.close()
            
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            if self.cache_ext_policy and self.cache_ext_policy.has_started:
                self.cache_ext_policy.stop()
        
        time.sleep(2)
        enable_smt()

    def parse_results(self, stdout: str) -> BenchResults:
        try:
            lines = stdout.strip().split('\n')
            last_line = ""
            for line in reversed(lines):
                if line.strip().startswith("{") and line.strip().endswith("}"):
                    last_line = line
                    break
            
            if not last_line:
                raise Exception("No JSON output found")

            results = json.loads(last_line)
            return BenchResults(results)
        except Exception as e:
            log.error(f"Failed to parse results: {e}")
            log.error(f"Stdout was: {stdout}")
            return BenchResults({})

def run_internal_worker():
    parser = argparse.ArgumentParser(description="ClickBench Internal Worker")
    parser.add_argument("--clickhouse-bin", type=str, required=True)
    parser.add_argument("--queries-file", type=str, required=True)
    parser.add_argument("--iterations", type=int, default=1)
    
    args = parser.parse_args()

    with open(args.queries_file, 'r') as f:
        queries = [line.strip() for line in f if line.strip()]

    results = {}
    total_time = 0.0
    
    for q_idx, query in enumerate(queries):
        query_latencies = []
        
        for i in range(args.iterations):
            if not query.endswith(';'):
                query += ';'
            query += '\n'

            cmd = [
                args.clickhouse_bin, "client",
                "--time",
                "--format=Null",
                "--query", query
            ]
            
            try:
                start_time = time.time()
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                out, err = proc.communicate()
                end_time = time.time()
                
                if proc.returncode != 0:
                    sys.stderr.write(f"Query {q_idx} failed: {err}\n")
                    continue
                
                latency = 0.0
                match = re.search(r"([0-9\.]+)\s+sec\.", err)
                if match:
                    latency = float(match.group(1))
                else:
                    latency = end_time - start_time
                
                query_latencies.append(latency)
                
            except Exception as e:
                sys.stderr.write(f"Error running query {q_idx}: {e}\n")
        
        if query_latencies:
            avg_latency = sum(query_latencies) / len(query_latencies)
            results[f"q{q_idx}_latency"] = avg_latency
            results[f"q{q_idx}_latencies"] = query_latencies
            total_time += avg_latency

    results["total_time_s"] = total_time
    results["score"] = total_time
    
    # Print ONLY the JSON result to stdout
    print(json.dumps(results))

def main():
    # Check if this is the internal worker call
    if "--run-internal" in sys.argv:
        # Remove the flag so argparse doesn't complain (though we use a fresh parser anyway)
        sys.argv.remove("--run-internal")
        run_internal_worker()
        return

    # Normal Driver Mode
    try:
        logging.basicConfig(level=logging.INFO)
        bench = ClickBenchBenchmark()
        bench.benchmark()
    except Exception as e:
        log.error("Error in main: %s", e)
        log.info("Cleaning up")
        for task in CLEANUP_TASKS:
            task()
        log.error("Re-raising exception")
        raise e

if __name__ == "__main__":
    main()
