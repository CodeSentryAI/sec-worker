#!/usr/bin/env python3
"""Phase-timed slither benchmark driver (A/B/C cost measurement).

Run under the bench venv python. One invocation = one (repo, mode) measurement.
Task JSON on stdin, result JSON on stdout, logs on stderr.

Phases:
  acquire         (orchestrator-side: repo copy = clone proxy; not timed here)
  compile_s       solc --standard-json over all sources -> one CryticCompile unit
  bundle_write_s  pickle the compilation unit ("CompilationBundle" cache write)
  cache_load_s    unpickle the bundle (cache hit cost; proxy for a Rust loader)
  model_s         Slither semantic model construction (CFG/SlithIR parse)
  detectors_s     all registered detectors, first run on the model
  detectors_repeat_s  same detectors again on the warm model (detector-only cost)

Modes:
  compile+analyze  compile -> bundle -> load -> analyze
  analyze          load existing bundle -> analyze (compilation cached)
"""
import glob
import json
import os
import pickle
import resource
import signal
import subprocess
import sys
import threading
import time


def log(*args):
    print(*args, file=sys.stderr, flush=True)


def self_maxrss_mb():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


class AnalysisTimeout(Exception):
    pass


def register_detectors(sl):
    """The Slither object ships with zero registered detectors when used as a
    library; the CLI registers all_detectors in __main__. Mirror that."""
    from slither.detectors import all_detectors
    from slither.detectors.abstract_detector import AbstractDetector

    for name in dir(all_detectors):
        obj = getattr(all_detectors, name)
        if isinstance(obj, type) and issubclass(obj, AbstractDetector):
            try:
                sl.register_detector(obj)
            except Exception as e:  # noqa: BLE001
                log(f"register failed for {name}: {e}")


class RssSampler:
    """Sample VmRSS from /proc/self/status at a fixed interval; report avg+peak."""

    def __init__(self, interval_s=0.02):
        self.interval_s = interval_s
        self.samples = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _read_rss_mb(self):
        try:
            with open("/proc/self/status", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("VmRSS:"):
                        return int(line.split()[1]) / 1024.0
        except OSError:
            pass
        return 0.0

    def _run(self):
        while not self._stop.is_set():
            self.samples.append(self._read_rss_mb())
            self._stop.wait(self.interval_s)

    def __enter__(self):
        self.samples.append(self._read_rss_mb())
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(timeout=1)
        self.samples.append(self._read_rss_mb())
        return False

    @property
    def peak_mb(self):
        return max(self.samples) if self.samples else 0.0

    @property
    def avg_mb(self):
        return sum(self.samples) / len(self.samples) if self.samples else 0.0


def enable_model_profiling():
    """Turn on slither's built-in PhaseTimer and add finer-grained phases for
    the _analyze_* sub-steps of analyze_contracts (inheritance/CFG/bodies)."""
    from slither.utils.timing import PhaseTimer

    timer = PhaseTimer.get()
    timer.enabled = True
    timer.reset()

    from slither.solc_parsing.slither_compilation_unit_solc import SlitherCompilationUnitSolc

    for part in ["_analyze_all_enums", "_analyze_first_part", "_analyze_second_part", "_analyze_third_part", "_analyze_using_for"]:
        orig = getattr(SlitherCompilationUnitSolc, part)

        def make_wrapper(orig_fn, part_name):
            def inner(self, *args, **kwargs):
                with timer.phase(f"cfg_{part_name.lstrip('_')}"):
                    return orig_fn(self, *args, **kwargs)
            return inner

        setattr(SlitherCompilationUnitSolc, part, make_wrapper(orig, part))
    return timer


def compile_bundle(task, result):
    """solc --standard-json over all sources -> CryticCompile -> pickle."""
    from crytic_compile import CryticCompile
    from crytic_compile.platform.solc_standard_json import SolcStandardJson

    files = sorted(glob.glob(os.path.join(task["targetDir"], "**", "*.sol"), recursive=True))
    if not files:
        raise RuntimeError(f"no .sol files under {task['targetDir']}")
    result["metrics"]["source_files"] = len(files)

    plat = SolcStandardJson()
    for f in files:
        plat.add_source_file(f)
    input_path = task["bundlePath"] + ".stdin.json"
    with open(input_path, "w", encoding="utf-8") as fh:
        json.dump(plat.to_dict(), fh)

    t0 = time.time()
    cc = CryticCompile(
        input_path,
        compile_force_framework="Solc-json",
        solc=task["solc"],
        solc_args=f"--allow-paths {task['repoRoot']}",
        solc_working_dir=task["repoRoot"],
    )
    result["phases"]["compile_s"] = round(time.time() - t0, 3)

    t0 = time.time()
    with open(task["bundlePath"], "wb") as f:
        pickle.dump(cc, f, protocol=pickle.HIGHEST_PROTOCOL)
    result["phases"]["bundle_write_s"] = round(time.time() - t0, 3)
    result["metrics"]["bundle_mb"] = round(os.path.getsize(task["bundlePath"]) / (1024 * 1024), 2)


def main():
    task = json.loads(sys.stdin.read())
    mode = task["mode"]  # "compile+analyze" | "analyze"
    timeout_analyze = int(task.get("timeoutAnalyze", 900))

    result = {
        "name": task["name"],
        "mode": mode,
        "solc": task.get("solc"),
        "phases": {},
        "metrics": {},
        "errors": [],
    }

    if mode == "compile+analyze":
        try:
            compile_bundle(task, result)
        except Exception as e:  # noqa: BLE001
            result["errors"].append(f"compile failed: {str(e)[:500]}")
            json.dump(result, sys.stdout, indent=1)
            sys.stdout.write("\n")
            return

    signal.signal(signal.SIGALRM, lambda *a: (_ for _ in ()).throw(AnalysisTimeout()))
    signal.alarm(timeout_analyze)
    timer = enable_model_profiling()
    with RssSampler() as sampler:
        try:
            t0 = time.time()
            with open(task["bundlePath"], "rb") as f:
                cc = pickle.load(f)
            result["phases"]["cache_load_s"] = round(time.time() - t0, 3)

            from slither import Slither

            t0 = time.time()
            sl = Slither(cc)
            result["phases"]["model_s"] = round(time.time() - t0, 3)
            result["metrics"]["contracts"] = len(sl.contracts)
            result["metrics"]["functions"] = sum(len(c.functions) for c in sl.contracts)

            register_detectors(sl)

            t0 = time.time()
            findings = sl.run_detectors()
            result["phases"]["detectors_s"] = round(time.time() - t0, 3)
            result["metrics"]["detector_findings"] = sum(len(r) for r in findings)
            result["metrics"]["detectors_run"] = len(findings)

            t0 = time.time()
            findings2 = sl.run_detectors()
            result["phases"]["detectors_repeat_s"] = round(time.time() - t0, 3)
            result["metrics"]["detector_findings_repeat"] = sum(len(r) for r in findings2)
        except AnalysisTimeout:
            result["errors"].append(f"analysis timed out after {timeout_analyze}s")
        except Exception as e:  # noqa: BLE001
            result["errors"].append(f"analysis failed: {str(e)[:500]}")
        finally:
            signal.alarm(0)

        result["metrics"]["analysis_rss_mb"] = round(sampler.peak_mb, 1)
        result["metrics"]["avg_rss_mb"] = round(sampler.avg_mb, 1)
        result["phases"]["model_stages"] = timer.report()
    json.dump(result, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
