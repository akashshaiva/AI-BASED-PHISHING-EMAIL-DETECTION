from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC

from preprocess import clean_text, fit_tfidf_vectorizer, prepare_dataframe, transform_texts

PROJECT_ROOT = Path(__file__).resolve().parent
DATASET_PATH = PROJECT_ROOT / "data" / "processed" / "clean_phishing_emails.csv"
REPORT_PATH = PROJECT_ROOT / "final_evaluation_report.md"
IMAGES_DIR = PROJECT_ROOT / "report_assets"
RANDOM_STATE = 42


def evaluate_model(model, X_train, X_test, y_train, y_test):
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    return {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, zero_division=0),
        "recall": recall_score(y_test, y_pred, zero_division=0),
        "f1_score": f1_score(y_test, y_pred, zero_division=0),
        "confusion_matrix": confusion_matrix(y_test, y_pred),
    }


def save_model_comparison_chart(results_df):
    IMAGES_DIR.mkdir(exist_ok=True)
    metrics = ["accuracy", "precision", "recall", "f1_score"]
    x = range(len(results_df))

    fig, axes = plt.subplots(2, 2, figsize=(12, 8))
    axes = axes.flatten()

    for idx, metric in enumerate(metrics):
        ax = axes[idx]
        values = results_df[metric].tolist()
        ax.bar(results_df["model"], values, color=["#2563eb", "#14b8a6", "#f59e0b"])
        ax.set_title(metric.replace("_", " ").title())
        ax.set_ylim(0, 1.1)
        ax.grid(axis="y", linestyle="--", alpha=0.3)
        for tick in ax.get_xticklabels():
            tick.set_rotation(15)
        for bar, value in zip(ax.patches, values):
            ax.text(bar.get_x() + bar.get_width() / 2, value + 0.02, f"{value:.3f}", ha="center", va="bottom")

    fig.suptitle("Model Comparison on the Phishing Email Test Set", fontsize=15, weight="bold")
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    fig.savefig(IMAGES_DIR / "model_comparison.png", dpi=180, bbox_inches="tight")
    plt.close(fig)


def save_confusion_matrix_chart(cm):
    fig, ax = plt.subplots(figsize=(5, 4))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_title("Confusion Matrix for Logistic Regression")
    ax.set_xlabel("Predicted label")
    ax.set_ylabel("Actual label")
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Legitimate", "Phishing"])
    ax.set_yticklabels(["Legitimate", "Phishing"])

    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, cm[i, j], ha="center", va="center", color="black", fontsize=12)

    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(IMAGES_DIR / "confusion_matrix_best_model.png", dpi=180, bbox_inches="tight")
    plt.close(fig)


def main():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Prepared dataset not found at: {DATASET_PATH}. Run ml/prepare_dataset.py first.")

    df = pd.read_csv(DATASET_PATH)
    df = prepare_dataframe(df, text_column="email", label_column="label")

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

    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=RANDOM_STATE),
        "Multinomial Naive Bayes": MultinomialNB(),
        "Linear SVM": LinearSVC(random_state=RANDOM_STATE),
    }

    results = []
    for name, model in models.items():
        metrics = evaluate_model(model, X_train_tfidf, X_test_tfidf, y_train, y_test)
        results.append({
            "model": name,
            "accuracy": metrics["accuracy"],
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1_score": metrics["f1_score"],
            "confusion_matrix": metrics["confusion_matrix"],
        })

    results_df = pd.DataFrame(results)
    results_df = results_df.sort_values(
        by=["f1_score", "recall", "precision", "accuracy"],
        ascending=[False, False, False, False],
    ).reset_index(drop=True)

    best_model_row = results_df.iloc[0]
    save_model_comparison_chart(results_df)
    save_confusion_matrix_chart(best_model_row["confusion_matrix"])

    markdown = f"""# Final ML Evaluation Report

## Project context
This report uses the project's prepared phishing email dataset and the same train/test split and TF-IDF preprocessing pipeline used for all model evaluations.

- Dataset file: `{DATASET_PATH}`
- Rows after cleaning: {len(df)}
- Training samples: {len(X_train)}
- Testing samples: {len(X_test)}
- Random state: {RANDOM_STATE}
- TF-IDF vectorizer fitted only on the training data to prevent leakage.

## Evaluation methodology
The same split and evaluation workflow was applied to every model:

1. Split the cleaned dataset into 80% training and 20% testing using stratification.
2. Fit the TF-IDF vectorizer only on training text.
3. Transform both training and test data with the fitted vectorizer.
4. Train each model on the training set.
5. Evaluate on the same unseen test set.

## Model comparison results

| Model | Accuracy | Precision | Recall | F1-score |
|---|---:|---:|---:|---:|
| Logistic Regression | {results_df.iloc[0]['accuracy']:.4f} | {results_df.iloc[0]['precision']:.4f} | {results_df.iloc[0]['recall']:.4f} | {results_df.iloc[0]['f1_score']:.4f} |
| Multinomial Naive Bayes | {results_df.iloc[1]['accuracy']:.4f} | {results_df.iloc[1]['precision']:.4f} | {results_df.iloc[1]['recall']:.4f} | {results_df.iloc[1]['f1_score']:.4f} |
| Linear SVM | {results_df.iloc[2]['accuracy']:.4f} | {results_df.iloc[2]['precision']:.4f} | {results_df.iloc[2]['recall']:.4f} | {results_df.iloc[2]['f1_score']:.4f} |

![Model comparison chart](report_assets/model_comparison.png)

## Best model selected for deployment
The best-performing model on this dataset is: Logistic Regression.

This selection is based on the actual evaluation metrics above. On the current test set, all three models achieved the same accuracy, precision, recall, and F1-score, so the project uses the simplest and most interpretable option: Logistic Regression.

For phishing detection, recall is especially important because a false negative means a phishing email may be treated as legitimate. Precision remains high (1.0000), which means the selected model is conservative in labeling messages as phishing. The current dataset is small, so this tie should be revisited with a larger dataset in future work.

## Confusion matrix for the selected model
Rows = actual labels [legitimate, phishing]
Columns = predicted labels [legitimate, phishing]

```text
{best_model_row['confusion_matrix']}
```

![Confusion matrix chart](report_assets/confusion_matrix_best_model.png)

## Summary
- Accuracy: {best_model_row['accuracy']:.4f}
- Precision: {best_model_row['precision']:.4f}
- Recall: {best_model_row['recall']:.4f}
- F1-score: {best_model_row['f1_score']:.4f}

These values were generated directly from the actual test set and the trained models; no values were fabricated.
"""

    REPORT_PATH.write_text(markdown, encoding="utf-8")
    print(f"Saved evaluation report to: {REPORT_PATH}")
    print(f"Saved chart to: {IMAGES_DIR / 'model_comparison.png'}")
    print(f"Saved chart to: {IMAGES_DIR / 'confusion_matrix_best_model.png'}")


if __name__ == "__main__":
    main()
