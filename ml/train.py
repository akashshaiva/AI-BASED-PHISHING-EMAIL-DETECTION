from pathlib import Path

import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from preprocess import clean_text, fit_tfidf_vectorizer, prepare_dataframe, transform_texts


PROJECT_ROOT = Path(__file__).resolve().parent
DATASET_PATH = PROJECT_ROOT / "data" / "processed" / "clean_phishing_emails.csv"
MODEL_DIR = PROJECT_ROOT / "models"
MODEL_DIR.mkdir(exist_ok=True)
RANDOM_STATE = 42


def main():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Prepared dataset not found at: {DATASET_PATH}. Run ml/prepare_dataset.py first."
        )

    df = pd.read_csv(DATASET_PATH)
    df = prepare_dataframe(df, text_column="email", label_column="label")

    if df.empty:
        raise ValueError("Prepared dataset is empty after cleaning and validation.")

    X = df["email"].map(clean_text)
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    vectorizer = fit_tfidf_vectorizer(X_train, ngram_range=(1, 2), min_df=1)

    X_train_tfidf = transform_texts(vectorizer, X_train)
    X_test_tfidf = transform_texts(vectorizer, X_test)

    model = LogisticRegression(max_iter=1000, random_state=RANDOM_STATE)
    model.fit(X_train_tfidf, y_train)

    y_pred = model.predict(X_test_tfidf)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    print("Dataset path:", DATASET_PATH)
    print("Rows after cleaning:", len(df))
    print("Train size:", len(X_train))
    print("Test size:", len(X_test))
    print("Accuracy:", round(accuracy, 4))
    print("Precision:", round(precision, 4))
    print("Recall:", round(recall, 4))
    print("F1-score:", round(f1, 4))
    print("Confusion matrix:")
    print(cm)

    vectorizer_path = MODEL_DIR / "tfidf_vectorizer.joblib"
    model_path = MODEL_DIR / "logistic_regression.joblib"

    joblib.dump(vectorizer, vectorizer_path)
    joblib.dump(model, model_path)

    print(f"Saved vectorizer to: {vectorizer_path}")
    print(f"Saved model to: {model_path}")


if __name__ == "__main__":
    main()
