"""
Train Gradient Boosting classifier on cleaned_dataset.csv.
Uses all 87 pre-computed features from dataset_phishing.csv.
GradientBoosting chosen for best accuracy on this tabular dataset.
"""

import sys
import json
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, classification_report
)

CLEAN_PATH   = Path(__file__).parent / "cleaned_dataset.csv"
MODEL_DIR    = Path(__file__).parent.parent / "backend" / "model"
MODEL_PATH   = MODEL_DIR / "phishing_model.pkl"
META_PATH    = MODEL_DIR / "model_meta.json"
RANDOM_STATE = 42

# All 87 feature columns from dataset_phishing.csv (excluding url and label)
FEATURE_COLS = [
    "length_url", "length_hostname", "ip", "nb_dots", "nb_hyphens",
    "nb_at", "nb_qm", "nb_and", "nb_or", "nb_eq", "nb_underscore",
    "nb_tilde", "nb_percent", "nb_slash", "nb_star", "nb_colon",
    "nb_comma", "nb_semicolumn", "nb_dollar", "nb_space", "nb_www",
    "nb_com", "nb_dslash", "http_in_path", "https_token",
    "ratio_digits_url", "ratio_digits_host", "punycode", "port",
    "tld_in_path", "tld_in_subdomain", "abnormal_subdomain",
    "nb_subdomains", "prefix_suffix", "random_domain",
    "shortening_service", "path_extension", "nb_redirection",
    "nb_external_redirection", "length_words_raw", "char_repeat",
    "shortest_words_raw", "shortest_word_host", "shortest_word_path",
    "longest_words_raw", "longest_word_host", "longest_word_path",
    "avg_words_raw", "avg_word_host", "avg_word_path", "phish_hints",
    "domain_in_brand", "brand_in_subdomain", "brand_in_path",
    "suspecious_tld", "statistical_report", "nb_hyperlinks",
    "ratio_intHyperlinks", "ratio_extHyperlinks", "ratio_nullHyperlinks",
    "nb_extCSS", "ratio_intRedirection", "ratio_extRedirection",
    "ratio_intErrors", "ratio_extErrors", "login_form",
    "external_favicon", "links_in_tags", "submit_email",
    "ratio_intMedia", "ratio_extMedia", "sfh", "iframe",
    "popup_window", "safe_anchor", "onmouseover", "right_clic",
    "empty_title", "domain_in_title", "domain_with_copyright",
    "whois_registered_domain", "domain_registration_length",
    "domain_age", "web_traffic", "dns_record", "google_index",
    "page_rank",
]


def train():
    if not CLEAN_PATH.exists():
        print("[ERROR] cleaned_dataset.csv not found. Run: python preprocess.py")
        sys.exit(1)

    df = pd.read_csv(CLEAN_PATH, low_memory=False)
    print(f"Training on {len(df):,} samples.")
    print(f"Labels: {df['label'].value_counts().to_dict()}")

    # Use only columns that exist in the dataset
    available = [c for c in FEATURE_COLS if c in df.columns]
    print(f"Using {len(available)} features.")

    X = df[available].fillna(0).values
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )

    clf = GradientBoostingClassifier(
        n_estimators=200,
        learning_rate=0.1,
        max_depth=5,
        subsample=0.8,
        random_state=RANDOM_STATE,
    )
    print("Training Gradient Boosting (200 estimators)...")
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)

    print(f"\n=== Results ===")
    print(f"Accuracy : {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall   : {rec:.4f}")
    print(f"F1-Score : {f1:.4f}")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    print(f"Model saved -> {MODEL_PATH}")

    meta = {
        "feature_names":  available,
        "n_features":     len(available),
        "model_type":     "GradientBoosting",
        "accuracy":       round(acc,  4),
        "precision":      round(prec, 4),
        "recall":         round(rec,  4),
        "f1_score":       round(f1,   4),
        "train_samples":  len(X_train),
        "test_samples":   len(X_test),
    }
    with open(META_PATH, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"Metadata saved -> {META_PATH}")


if __name__ == "__main__":
    train()
