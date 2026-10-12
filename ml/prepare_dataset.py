from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split


PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
SOURCE_PATH = DATA_DIR / "phishing_emails.csv"
OUTPUT_DIR = DATA_DIR / "processed"
OUTPUT_DIR.mkdir(exist_ok=True)

CLEAN_PATH = OUTPUT_DIR / "clean_phishing_emails.csv"
TRAIN_PATH = OUTPUT_DIR / "train.csv"
TEST_PATH = OUTPUT_DIR / "test.csv"


def detect_text_column(df):
    text_candidates = [
        col
        for col in df.columns
        if col.lower() in {"email", "text", "message", "body", "content", "email_text"}
    ]
    if text_candidates:
        return text_candidates[0]

    object_columns = [col for col in df.columns if df[col].dtype == "object"]
    for col in object_columns:
        sample = df[col].dropna().astype(str)
        if sample.empty:
            continue
        if sample.str.len().median() > 20:
            return col
    raise ValueError("Could not detect the text/email column automatically.")


def detect_label_column(df):
    label_candidates = [
        col
        for col in df.columns
        if col.lower() in {"label", "target", "class", "category", "result", "prediction"}
        or "label" in col.lower()
        or "class" in col.lower()
    ]
    if label_candidates:
        return label_candidates[0]

    for col in df.columns:
        unique_values = df[col].dropna().astype(str).str.lower().unique()
        normalized = {str(v).strip() for v in unique_values}
        if normalized & {"legitimate", "phishing", "spam", "ham", "safe", "unsafe", "0", "1"}:
            return col

    raise ValueError("Could not detect the label/class column automatically.")


def normalize_label(value):
    if pd.isna(value):
        return None

    normalized = str(value).strip().lower()
    mapping = {
        "legitimate": "legitimate",
        "safe": "legitimate",
        "ham": "legitimate",
        "0": "legitimate",
        "not_phishing": "legitimate",
        "phishing": "phishing",
        "spam": "phishing",
        "unsafe": "phishing",
        "1": "phishing",
    }
    return mapping.get(normalized, normalized)


def print_distribution(df, label_column):
    print("\nClass distribution after normalization:")
    print(df[label_column].value_counts().to_string())
    print("\nPercentages:")
    print((df[label_column].value_counts(normalize=True) * 100).round(2).to_string())


def main():
    if not SOURCE_PATH.exists():
        raise FileNotFoundError(f"Dataset file not found: {SOURCE_PATH}")

    original_df = pd.read_csv(SOURCE_PATH)
    print("Original dataset shape:", original_df.shape)
    print("Original columns:", list(original_df.columns))

    text_column = detect_text_column(original_df)
    label_column = detect_label_column(original_df)
    print(f"Detected text column: {text_column}")
    print(f"Detected label column: {label_column}")

    cleaned = original_df.copy()
    cleaned = cleaned[[text_column, label_column]].copy()
    cleaned.columns = ["email", "label"]

    cleaned = cleaned.dropna(subset=["email", "label"]).copy()
    cleaned["email"] = cleaned["email"].astype(str).str.strip()
    cleaned["label"] = cleaned["label"].astype(str).str.strip()
    cleaned = cleaned[cleaned["email"].str.len() > 0].copy()
    cleaned = cleaned.drop_duplicates(subset=["email", "label"]).copy()

    cleaned["label"] = cleaned["label"].map(normalize_label)
    cleaned = cleaned.dropna(subset=["label"]).copy()
    cleaned["label"] = cleaned["label"].astype(str).str.lower()

    print("\nRows removed for invalid/empty content:", len(original_df) - len(cleaned))
    print("Rows after cleaning:", len(cleaned))

    print_distribution(cleaned, "label")

    cleaned.to_csv(CLEAN_PATH, index=False)
    print(f"\nClean dataset saved to: {CLEAN_PATH}")

    X = cleaned["email"]
    y = cleaned["label"].map({"legitimate": 0, "phishing": 1})

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    train_df = pd.DataFrame({"email": X_train, "label": y_train})
    test_df = pd.DataFrame({"email": X_test, "label": y_test})

    train_df.to_csv(TRAIN_PATH, index=False)
    test_df.to_csv(TEST_PATH, index=False)

    print(f"Training split saved to: {TRAIN_PATH}")
    print(f"Testing split saved to: {TEST_PATH}")
    print(f"Training rows: {len(train_df)}")
    print(f"Testing rows: {len(test_df)}")


if __name__ == "__main__":
    main()
