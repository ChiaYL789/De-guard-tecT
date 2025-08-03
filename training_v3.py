#!/usr/bin/env python3
"""
training_v3.py – one-shot trainer for MalCommandGuard models
------------------------------------------------------------
Trains two independent classifiers:

1. URL classifier  – detects benign / suspicious / malicious links
2. CMD classifier  – detects benign / suspicious / malicious shell commands
                     (augmented with NLP-derived meta tokens)

Both models and their evaluation reports are written to the chosen --model-dir.
"""

import argparse
import io
import json
import logging
import sys
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from config import SAFE_DOMAINS
from nlp_features import augment              # meta-token generator
from security_utils import safe_open_read, safe_open_binary

print("🛠️  Hello—training_v3 is starting!")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(path: str) -> None:
    """Initialise console + file logging."""
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s: %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(path, mode='w', encoding='utf-8'),
        ],
    )


# ---------------------------------------------------------------------------
# Helpers for the URL dataset
# ---------------------------------------------------------------------------

def _host_is_trusted(host: str) -> bool:
    """
    Allow-list policy: host must be exactly a trusted domain or a subdomain of it.
    E.g., docs.python.org -> trusted because it endswith ".python.org".
    """
    h = (host or "").lower()
    for d in SAFE_DOMAINS:
        if h == d or h.endswith("." + d):
            return True
    return False


def clean_url_labels(df: pd.DataFrame) -> pd.DataFrame:
    """
    Force the label 'benign' only when the URL's hostname is a trusted
    domain or its subdomain. This avoids falsely whitelisting deceptive
    hosts like accounts.google.com.evil.tld.
    """
    def is_safe(u: str) -> bool:
        try:
            host = (urlsplit(u).hostname or "").lower()
            return _host_is_trusted(host)
        except Exception:
            return False

    mask = df["url"].map(is_safe)
    df.loc[mask, "label"] = "benign"
    return df


# ---------------------------------------------------------------------------
# Training – URL model
# ---------------------------------------------------------------------------

def train_url_model(csv_path: str, test_size: float, seed: int):
    logging.info("Loading URL CSV …")
    csv_text = safe_open_read(csv_path)              # secure file helper
    df = pd.read_csv(io.StringIO(csv_text)).dropna(subset=["url", "label"])
    df = clean_url_labels(df)

    X, y = df["url"], df["label"]
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=seed
    )

    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            max_features=50_000,
        )),
        ("clf", LogisticRegression(
            max_iter=1_000,
            class_weight="balanced",
            random_state=seed,
            # solver left as default ('lbfgs'); n_jobs not used by lbfgs
        )),
    ])

    model.fit(X_tr, y_tr)
    report = classification_report(y_te, model.predict(X_te), output_dict=True)
    return model, report


# ---------------------------------------------------------------------------
# Training – CMD model (text + NLP meta tokens)
# ---------------------------------------------------------------------------

def train_cmd_model(xlsx_path: str, test_size: float, seed: int):
    logging.info("Loading CMD XLSX …")

    # Secure file read (blocks path traversal)
    with safe_open_binary(xlsx_path) as fh:
        df = pd.read_excel(fh).dropna(subset=["prompt", "Label"])

    X = df["prompt"].apply(augment)        # append meta-tokens
    y = df["Label"]

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=seed
    )

    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=15_000,
            token_pattern=r"(?u)\b\w+\b",   # keeps meta tokens intact
        )),
        ("clf", RandomForestClassifier(
            n_estimators=300,
            class_weight="balanced",
            random_state=seed,
            n_jobs=-1,
        )),
    ])

    model.fit(X_tr, y_tr)
    report = classification_report(y_te, model.predict(X_te), output_dict=True)
    return model, report


# ---------------------------------------------------------------------------
# Utility – save JSON nicely
# ---------------------------------------------------------------------------

def save_json(obj, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(obj, fp, indent=2)
    logging.info("Saved %s", path)


# ---------------------------------------------------------------------------
# Main entry-point
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Train URL & CMD models for MalCommandGuard")
    ap.add_argument("--url-csv",  default="dataset/balanced_urls.csv",
                    help="Path to CSV of labelled URLs (columns: url,label)")
    ap.add_argument("--cmd-xlsx", default="dataset/windows_cmd_analyzed.xlsx",
                    help="Path to Excel of labelled commands (columns: prompt,Label)")
    ap.add_argument("--model-dir", default="models",
                    help="Output directory for .pkl models and JSON reports")
    ap.add_argument("--test-size", type=float, default=0.20,
                    help="Fraction of data used for hold-out evaluation")
    ap.add_argument("--seed", type=int, default=42,
                    help="Random seed for reproducibility")
    args = ap.parse_args()

    Path(args.model_dir).mkdir(parents=True, exist_ok=True)
    setup_logging(Path(args.model_dir) / "training.log")

    logging.info("Versions  pandas=%s  numpy=%s  sklearn=%s",
                 pd.__version__, np.__version__, sklearn.__version__)

    # ---------------- Train URL model ----------------
    url_model, url_report = train_url_model(args.url_csv, args.test_size, args.seed)
    joblib.dump(url_model, Path(args.model_dir) / "url_classifier.pkl", compress=3)
    save_json(url_report,         Path(args.model_dir) / "url_report.json")

    # ---------------- Train CMD model ----------------
    cmd_model, cmd_report = train_cmd_model(args.cmd_xlsx, args.test_size, args.seed)
    joblib.dump(cmd_model, Path(args.model_dir) / "cmd_classifier.pkl", compress=3)
    save_json(cmd_report,         Path(args.model_dir) / "cmd_report.json")

    logging.info("✅ Training complete. Models saved to %s", args.model_dir)


if __name__ == "__main__":
    main()
