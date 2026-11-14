"""
Preprocess dataset_phishing.csv -> cleaned_dataset.csv
Keeps url + all 87 feature columns + label (0=legitimate, 1=phishing)
"""

import sys
import pandas as pd
from pathlib import Path

RAW_PATH   = Path(__file__).parent / "dataset_phishing.csv"
CLEAN_PATH = Path(__file__).parent / "cleaned_dataset.csv"


def preprocess():
    if not RAW_PATH.exists():
        print(f"[ERROR] dataset_phishing.csv not found at {RAW_PATH}")
        sys.exit(1)

    print(f"Loading {RAW_PATH.name} ...")
    df = pd.read_csv(RAW_PATH, low_memory=False)
    print(f"Loaded {len(df):,} records with {len(df.columns)} columns.")

    df.columns = [c.strip() for c in df.columns]

    # Map status -> binary label
    df["label"] = df["status"].map({"legitimate": 0, "phishing": 1})
    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int)
    df = df.drop(columns=["status"])

    # Drop rows with missing url
    df = df.dropna(subset=["url"])
    df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)

    print(f"Cleaned: {len(df):,} records.")
    print(f"Labels: {df['label'].value_counts().to_dict()}")

    df.to_csv(CLEAN_PATH, index=False)
    print(f"Saved -> {CLEAN_PATH}")
    return df


if __name__ == "__main__":
    preprocess()
