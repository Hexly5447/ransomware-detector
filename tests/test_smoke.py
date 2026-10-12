"""Smoke test: verifies imports, feature extraction, and model loading.

Run:  python tests\test_smoke.py
Exit: code 0 on success, 1 on failure.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

FAILED = []


def check(name, fn):
    try:
        fn()
        print(f"  [PASS] {name}")
    except Exception as exc:
        FAILED.append(name)
        print(f"  [FAIL] {name}: {exc}")


def main():
    print("== Smoke test ==")

    def imports():
        import src.feature_extractor
        import src.monitor
        import src.train_model
        import src.predict
        import src.detector
        import src.gui

    check("all src modules import", imports)

    def feature_names():
        from src.feature_extractor import FEATURE_NAMES
        assert len(FEATURE_NAMES) == 14, f"expected 14, got {len(FEATURE_NAMES)}"

    check("FEATURE_NAMES has 14 entries", feature_names)

    def window_features():
        import tempfile
        from pathlib import Path as P
        from src.feature_extractor import SlidingWindow, FileEvent
        import time
        w = SlidingWindow(window_sec=5.0)
        now = time.time()
        with tempfile.TemporaryDirectory(dir=str(ROOT)) as td:
            for i in range(10):
                f = P(td) / f"f{i}.bin"
                f.write_bytes(bytes([(i * 37 + j) % 256 for j in range(512)]))
                w.add_event(FileEvent(timestamp=now, event_type="modified",
                                      src_path=f))
            feats = w.compute_features()
        assert isinstance(feats, dict) and feats, "empty features"
        assert "entropy_avg" in feats

    check("SlidingWindow produces features", window_features)

    def model_loads():
        import joblib
        p = ROOT / "models" / "rf_model.pkl"
        assert p.exists(), "run 'python main.py train' first"
        m = joblib.load(p)
        assert hasattr(m, "predict_proba")

    check("Random Forest model loads", model_loads)

    def metrics_ok():
        p = ROOT / "models" / "metrics.json"
        assert p.exists(), "run 'python main.py train' first"
        d = json.loads(p.read_text(encoding="utf-8"))
        assert d, "metrics.json empty"

    check("metrics.json readable", metrics_ok)

    def gui_import():
        from src.gui import RansomwareGUI, run_gui

    check("GUI classes import", gui_import)

    def simulator_safe():
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "ransomware_simulator", ROOT / "simulator" / "ransomware_simulator.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert hasattr(mod, "safety_check"), "safety_check missing"

    check("simulator safety_check present", simulator_safe)

    print(f"== {len(FAILED)} failure(s) ==")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
