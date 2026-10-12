import argparse
from functools import lru_cache
from pathlib import Path

import joblib

from preprocess import clean_text

MODEL_DIR = Path(__file__).resolve().parent / "models"


@lru_cache(maxsize=1)
def load_model_assets():
    vectorizer_path = MODEL_DIR / "tfidf_vectorizer.joblib"
    model_path = MODEL_DIR / "logistic_regression.joblib"

    if not vectorizer_path.exists() or not model_path.exists():
        raise FileNotFoundError(
            "Model files not found. Train the model first using ml/train.py."
        )

    vectorizer = joblib.load(vectorizer_path)
    model = joblib.load(model_path)
    return vectorizer, model


def predict_email(text):
    """Return a production-ready phishing prediction for a single email string.

    The selected model is Logistic Regression, chosen because it tied with the other
    evaluated models on the actual dataset and is the simplest, most interpretable
    deployment choice.
    """
    if text is None:
        raise ValueError("Email text is required.")

    cleaned_text = clean_text(text)
    if not cleaned_text.strip():
        raise ValueError("Email text cannot be empty after cleaning.")

    vectorizer, model = load_model_assets()
    features = vectorizer.transform([cleaned_text])
    prediction = int(model.predict(features)[0])

    result = {
        "prediction": prediction,
        "label": "phishing" if prediction == 1 else "legitimate",
    }

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(features)[0]
        result["confidence"] = float(max(probabilities))
        result["probabilities"] = {
            "legitimate": float(probabilities[0]),
            "phishing": float(probabilities[1]),
        }

    return result


def main():
    parser = argparse.ArgumentParser(description="Predict phishing risk for a single email text.")
    parser.add_argument("text", help="Email text to classify.")
    args = parser.parse_args()

    result = predict_email(args.text)
    print(result)


if __name__ == "__main__":
    main()
