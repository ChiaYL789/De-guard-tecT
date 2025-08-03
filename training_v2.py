print("🛠️  Hello—training_v2 is starting!")

from security_utils import safe_open_read
import io
import os, sys, json, logging, argparse
import pandas as pd, numpy as np, sklearn
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

# ---------- helpers --------------------------------------------------
def setup_logging(path):
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s: %(message)s',
        handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler(path, mode='w')]
    )

SAFE_DOMAINS = {"github.com", "google.com", "youtube.com", "microsoft.com"}

def clean_url_labels(df):
    """Force‐set safe domains to benign."""
    mask = df["url"].str.contains('|'.join(SAFE_DOMAINS), case=False, na=False)
    df.loc[mask, "label"] = "benign"
    return df

# ---------- URL model ------------------------------------------------
def train_url_model(csv_path, test_size, seed):
    logging.info("Loading URL CSV …")
    df = pd.read_csv(csv_path).dropna(subset=["url", "label"])
    df = clean_url_labels(df)
    X, y = df["url"], df["label"]

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=test_size,
                                              stratify=y, random_state=seed)

    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3,5),
                                  max_features=50_000)),
        ("clf", LogisticRegression(max_iter=1000,
                                   class_weight="balanced",
                                   random_state=seed))
    ])
    pipe.fit(X_tr, y_tr)
    rep = classification_report(y_te, pipe.predict(X_te), output_dict=True)
    return pipe, rep

# ---------- CMD model (text only) -----------------------------------
def train_cmd_model(xlsx_path, test_size, seed):
    logging.info("Loading CMD XLSX …")
    df = pd.read_excel(xlsx_path).dropna(subset=["prompt", "Label"])
    X, y = df["prompt"], df["Label"]

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=test_size,
                                              stratify=y, random_state=seed)

    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1,2), max_features=10_000)),
        ("clf", RandomForestClassifier(n_estimators=200,
                                       class_weight="balanced",
                                       random_state=seed))
    ])
    pipe.fit(X_tr, y_tr)
    rep = classification_report(y_te, pipe.predict(X_te), output_dict=True)
    return pipe, rep

# ---------- save helper ---------------------------------------------
def save_json(obj, path):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)
    logging.info("Saved %s", path)

# ---------- main ----------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url-csv",  default="dataset/balanced_urls.csv")
    ap.add_argument("--cmd-xlsx", default="dataset/windows_cmd_analyzed.xlsx")
    ap.add_argument("--model-dir",default="models")
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--seed",      type=int,   default=42)
    args = ap.parse_args()

    os.makedirs(args.model_dir, exist_ok=True)
    setup_logging(os.path.join(args.model_dir, "training.log"))

    # Version log
    logging.info("Versions  pandas=%s  numpy=%s  sklearn=%s",
                 pd.__version__, np.__version__, sklearn.__version__)

    url_model, url_rep = train_url_model(args.url_csv, args.test_size, args.seed)
    joblib.dump(url_model, os.path.join(args.model_dir, "url_classifier.pkl"))
    save_json(url_rep, os.path.join(args.model_dir, "url_report.json"))

    cmd_model, cmd_rep = train_cmd_model(args.cmd_xlsx, args.test_size, args.seed)
    joblib.dump(cmd_model, os.path.join(args.model_dir, "cmd_classifier.pkl"))
    save_json(cmd_rep, os.path.join(args.model_dir, "cmd_report.json"))

if __name__ == "__main__":
    main()
