"""
predict.py — Load trained model and score feature vectors in real-time.

Provides RansomwarePredictor class for inference with probability
smoothing and configurable thresholds.
"""

from __future__ import annotations

import joblib
import numpy as np
from collections import deque
from pathlib import Path
from typing import Deque, Dict, List, Optional

from .feature_extractor import FEATURE_NAMES

MODELS_DIR = Path(__file__).resolve().parents[1] / "models"
DEFAULT_MODEL_PATH = MODELS_DIR / "rf_model.pkl"


class RansomwarePredictor:
    """
    Wrapper around trained classifier for real-time inference.

    Features:
    - Loads model from disk
    - Maintains prediction history for smoothing
    - Configurable decision threshold
    - Returns both class and probability
    """

    def __init__(
        self,
        model_path: Path = DEFAULT_MODEL_PATH,
        threshold: float = 0.7,
        smoothing_window: int = 1,
    ):
        # smoothing_window=1 -> classify on the current window's raw
        # probability (fastest response). Raise for more damping at the
        # cost of detection latency.
        self.model_path = model_path
        self.threshold = threshold
        self.smoothing_window = smoothing_window
        self._model = None
        self._prob_history: Deque[float] = deque(maxlen=smoothing_window)
        self._load_model()

    def _load_model(self):
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model not found: {self.model_path}. Run train first.")
        self._model = joblib.load(self.model_path)

    def predict(self, features: Dict[str, float]) -> Dict:
        """
        Score a single feature vector.
        Returns: {"label": "BENIGN"|"RANSOMWARE", "probability": float, "smoothed_prob": float, "raw_prob": float}
        """
        # Build a DataFrame with proper feature names to match model training
        # (avoids sklearn "does not have valid feature names" warning).
        import pandas as pd

        vec = pd.DataFrame(
            [[features.get(name, 0.0) for name in FEATURE_NAMES]],
            columns=FEATURE_NAMES,
            dtype=np.float32,
        )
        prob = float(self._model.predict_proba(vec)[0, 1])
        self._prob_history.append(prob)
        smoothed = float(np.mean(self._prob_history))
        label = "RANSOMWARE" if smoothed >= self.threshold else "BENIGN"
        return {
            "label": label,
            "probability": smoothed,
            "raw_prob": prob,
            "threshold": self.threshold,
        }

    def predict_batch(self, feature_list: List[Dict[str, float]]) -> List[Dict]:
        """Score multiple feature vectors at once (no smoothing)."""
        if not feature_list:
            return []
        import pandas as pd

        mat = pd.DataFrame(
            [[f.get(name, 0.0) for name in FEATURE_NAMES] for f in feature_list],
            columns=FEATURE_NAMES,
            dtype=np.float32,
        )
        probs = self._model.predict_proba(mat)[:, 1]
        results = []
        for prob in probs:
            label = "RANSOMWARE" if prob >= self.threshold else "BENIGN"
            results.append({"label": label, "probability": float(prob), "threshold": self.threshold})
        return results

    def reset_smoothing(self):
        self._prob_history.clear()


def load_predictor(model_path: Optional[Path] = None, **kwargs) -> RansomwarePredictor:
    """Factory function."""
    return RansomwarePredictor(model_path or DEFAULT_MODEL_PATH, **kwargs)


if __name__ == "__main__":
    from .feature_extractor import extract_features_from_events, FileEvent
    from pathlib import Path
    import time

    # Quick test with synthetic features
    predictor = load_predictor()

    # Benign-like
    benign = {
        "entropy_avg": 2.0, "entropy_max": 3.5,
        "file_create_rate": 0.5, "file_modify_rate": 1.0,
        "file_delete_rate": 0.1, "rename_rate": 0.05,
        "extension_change_rate": 0.0,
        "unique_extensions_new": 5.0,
        "suspicious_ext_ratio": 0.02,
        "bytes_written_rate": 10000.0,
        "avg_file_size": 50000.0,
        "ransom_note_detected": 0.0,
        "time_window_sec": 10.0,
        "event_count": 20.0,
    }
    print("Benign test:", predictor.predict(benign))

    # Ransomware-like
    ransom = {
        "entropy_avg": 7.5, "entropy_max": 7.9,
        "file_create_rate": 50.0, "file_modify_rate": 60.0,
        "file_delete_rate": 10.0, "rename_rate": 40.0,
        "extension_change_rate": 30.0,
        "unique_extensions_new": 1.0,
        "suspicious_ext_ratio": 0.95,
        "bytes_written_rate": 10000000.0,
        "avg_file_size": 200000.0,
        "ransom_note_detected": 1.0,
        "time_window_sec": 5.0,
        "event_count": 500.0,
    }
    print("Ransomware test:", predictor.predict(ransom))