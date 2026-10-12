import html
import re
import string

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer


LABEL_MAP = {
    "legitimate": 0,
    "safe": 0,
    "ham": 0,
    "not_phishing": 0,
    "0": 0,
    "phishing": 1,
    "spam": 1,
    "unsafe": 1,
    "1": 1,
}


def remove_html(text):
    if text is None:
        return ""
    text = html.unescape(str(text))
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&nbsp;|&#160;", " ", text, flags=re.IGNORECASE)
    return text


def normalize_whitespace(text):
    return re.sub(r"\s+", " ", str(text)).strip()


def clean_text(text):
    """Normalize email text while preserving phishing indicators such as urgency words, verbs, and URLs."""
    if isinstance(text, float) and np.isnan(text):
        return ""
    if text is None:
        return ""

    text = remove_html(text)
    text = text.lower()
    text = text.replace("\n", " ")
    text = re.sub(r"https?://\S+|www\.\S+", " url ", text, flags=re.IGNORECASE)
    text = re.sub(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", " email ", text)
    text = re.sub(r"\d+", " digit ", text)
    text = text.translate(str.maketrans("", "", string.punctuation))
    text = normalize_whitespace(text)
    return text


def prepare_dataframe(df, text_column="email", label_column="label"):
    """Validate, clean, normalize, and deduplicate a phishing dataset.

    The function is designed to work with the actual dataset schema discovered in this project:
    email, label.
    """
    df = df.copy()
    required_columns = {text_column, label_column}
    missing_columns = required_columns - set(df.columns)
    if missing_columns:
        raise ValueError(f"Dataset is missing required columns: {sorted(missing_columns)}")

    df = df[[text_column, label_column]].copy()
    df.columns = ["email", "label"]
    df = df.dropna(subset=["email", "label"]).copy()

    df["email"] = df["email"].map(clean_text)
    df = df[df["email"].str.len() > 0].copy()
    df = df.drop_duplicates(subset=["email", "label"]).copy()

    df["label"] = df["label"].astype(str).str.strip().str.lower()
    df["label"] = df["label"].map(lambda value: LABEL_MAP.get(value, value))
    df = df.dropna(subset=["label"]).copy()
    df["label"] = df["label"].astype(int)
    return df


def fit_tfidf_vectorizer(texts, *, ngram_range=(1, 2), min_df=1, max_features=None):
    vectorizer = TfidfVectorizer(
        lowercase=False,
        ngram_range=ngram_range,
        min_df=min_df,
        max_features=max_features,
        token_pattern=r"(?u)\b\w+\b",
    )
    vectorizer.fit(texts)
    return vectorizer


def transform_texts(vectorizer, texts):
    return vectorizer.transform(texts)
