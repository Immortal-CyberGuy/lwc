import argparse

from src.attacks.eavesdrop_demo import run_demo as run_eavesdrop_demo
from src.attacks.mitm_demo import run_demo as run_mitm_demo
from src.attacks.replay_demo import run_demo as run_replay_demo
from src.benchmark.bench_runner import run_benchmarks, run_repeated_benchmarks
from src.benchmark.visualize import generate_all_charts


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Secure Wireless LWC project entry point.")
    parser.add_argument(
        "command",
        choices=[
            "benchmark_quick",
            "benchmark_full",
            "benchmark_repeat_quick",
            "benchmark_repeat_full",
            "charts",
            "attack_eavesdrop",
            "attack_replay",
            "attack_mitm",
            "attack_all",
            "dashboard",
        ],
        help="Action to execute.",
    )
    return parser


def main() -> None:
    args = _parser().parse_args()

    if args.command == "benchmark_quick":
        from src.benchmark.bench_runner import QUICK_ITERATIONS, QUICK_PAYLOAD_SIZES

        run_benchmarks(
            output_csv="results/benchmark_results.csv",
            iterations_map=QUICK_ITERATIONS,
            payload_sizes=QUICK_PAYLOAD_SIZES,
        )
        return

    if args.command == "benchmark_full":
        run_benchmarks(output_csv="results/benchmark_results.csv")
        return

    if args.command == "benchmark_repeat_quick":
        run_repeated_benchmarks(runs=3, output_dir="results", quick=True)
        return

    if args.command == "benchmark_repeat_full":
        run_repeated_benchmarks(runs=3, output_dir="results", quick=False)
        return

    if args.command == "charts":
        generate_all_charts(
            benchmark_csv="results/benchmark_results.csv",
            output_dir="results",
            attack_log_dir="results/attack_logs",
        )
        return

    if args.command == "attack_eavesdrop":
        run_eavesdrop_demo()
        return

    if args.command == "attack_replay":
        run_replay_demo()
        return

    if args.command == "attack_mitm":
        run_mitm_demo()
        return

    if args.command == "attack_all":
        run_eavesdrop_demo()
        run_replay_demo()
        run_mitm_demo()
        return

    if args.command == "dashboard":
        from src.ui.dashboard import run_dashboard

        run_dashboard(host="127.0.0.1", port=8091)
        return


if __name__ == "__main__":
    main()
