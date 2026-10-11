from pathlib import Path

import sklearn
from sklearn.datasets import load_breast_cancer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

BASE_DIR = Path(__file__).resolve().parents[1]
MODEL_DIR = BASE_DIR / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

# Temporary pipeline test using a built-in dataset.
# This is NOT a network intrusion detection dataset.
data = load_breast_cancer()
X_train, X_test, y_train, y_test = train_test_split(
    data.data,
    data.target,
    test_size=0.2,
    random_state=42,
    stratify=data.target,
)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

predictions = model.predict(X_test)

print("Pipeline test only — not an intrusion detection result.")
print(f"scikit-learn version: {sklearn.__version__}")
print(f"Training samples: {len(X_train)}")
print(f"Test samples: {len(X_test)}")
print(f"Test accuracy: {accuracy_score(y_test, predictions):.4f}")
print("\nClassification report:")
print(classification_report(y_test, predictions, target_names=data.target_names))

import joblib

model_path = MODEL_DIR / "pipeline_test.joblib"
joblib.dump(model, model_path)
print(f"Temporary test model saved to: {model_path}")
