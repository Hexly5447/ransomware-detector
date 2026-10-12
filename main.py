"""
main.py — CLI entry point for the Ransomware Detection System.

Subcommands:
    generate-data   Generate synthetic behavioral feature dataset
    train           Train Random Forest + boosting models
    monitor         Run console detector on a folder (default: test_folder/)
    gui             Launch Tkinter live dashboard
    simulate        Run the safe ransomware simulator (test_folder/ ONLY)

Examples:
    python main.py generate-data
    python main.py train
    python main.py monitor --path test_folder --duration 60
    python main.py gui
    python main.py simulate --files 30
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))


def cmd_generate_data(args):
    from src.train_model import generate_synthetic_data

    generate_synthetic_data(n_samples=args.samples)


def cmd_train(args):
    from src.train_model import main as train_main

    sys.argv = ["train_model", "--all"]
    train_main()


def cmd_monitor(args):
    from src.detector import run_detector

    path = Path(args.path)
    if not path.exists():
        print(f"[error] Path does not exist: {path}")
        sys.exit(1)

    run_detector(
        watch_path=path,
        window_sec=args.window,
        threshold=args.threshold,
        quarantine=not args.no_quarantine,
        kill_process=args.kill,
        duration=args.duration,
    )


def cmd_gui(args):
    try:
        import tkinter  # noqa: F401
    except ImportError:
        print("[error] Tkinter not available. Install python with Tk support.")
        sys.exit(1)

    from src.gui import run_gui

    run_gui()


def cmd_simulate(args):
    # Import simulator module directly
    sim_path = PROJECT_ROOT / "simulator" / "ransomware_simulator.py"
    if not sim_path.exists():
        print(f"[error] Simulator not found: {sim_path}")
        sys.exit(1)

    import importlib.util

    spec = importlib.util.spec_from_file_location("ransomware_simulator", sim_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.run(num_files=args.files, delay=args.delay)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Ransomware Detection System using ML and Behavioral Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # generate-data
    p_gen = sub.add_parser("generate-data", help="Generate synthetic feature dataset")
    p_gen.add_argument("--samples", type=int, default=250, help="Total rows (default 250)")
    p_gen.set_defaults(func=cmd_generate_data)

    # train
    p_train = sub.add_parser("train", help="Train RF + boosting models")
    p_train.set_defaults(func=cmd_train)

    # monitor
    p_mon = sub.add_parser("monitor", help="Run console detector")
    p_mon.add_argument("--path", default=str(PROJECT_ROOT / "test_folder"),
                       help="Folder to watch (default: test_folder)")
    p_mon.add_argument("--window", type=float, default=5.0,
                       help="Feature window seconds (default 5)")
    p_mon.add_argument("--threshold", type=float, default=0.7,
                       help="Detection threshold 0-1 (default 0.7)")
    p_mon.add_argument("--duration", type=float, default=60.0,
                       help="Run duration seconds (default 60)")
    p_mon.add_argument("--no-quarantine", action="store_true",
                       help="Disable quarantine (default: quarantine ON)")
    p_mon.add_argument("--kill", action="store_true",
                       help="Enable process kill on detection (OFF by default)")
    p_mon.set_defaults(func=cmd_monitor)

    # gui
    p_gui = sub.add_parser("gui", help="Launch Tkinter dashboard")
    p_gui.set_defaults(func=cmd_gui)

    # simulate
    p_sim = sub.add_parser("simulate",
                           help="Run SAFE ransomware simulator in test_folder only")
    p_sim.add_argument("--files", type=int, default=30,
                       help="Number of dummy files to create (default 30)")
    p_sim.add_argument("--delay", type=float, default=0.05,
                       help="Delay between operations seconds (default 0.05)")
    p_sim.set_defaults(func=cmd_simulate)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()