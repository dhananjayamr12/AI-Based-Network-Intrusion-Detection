import pandas as pd
import joblib

from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

# Project paths
PROJECT_DIR = Path("D:/AI-NIDS")

DATASET_PATH = PROJECT_DIR / "datasets" / "synthetic_network_traffic.csv"
MODEL_PATH = PROJECT_DIR / "ml-service" / "models" / "ids_model.joblib"

# Load synthetic dataset
print("Loading network traffic dataset...")

df = pd.read_csv(DATASET_PATH)

# Separate features and target
X = df.drop(columns=["label"])
y = df["label"]

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print(f"Training records: {len(X_train)}")
print(f"Testing records: {len(X_test)}")

# Create the Random Forest model
print("\nTraining Random Forest model...")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced"
)

# Train the model
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("\n========== MODEL EVALUATION ==========")
print(f"Test accuracy on synthetic data: {accuracy:.4f}")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=["Normal (synthetic)", "Attack (synthetic)"],
        zero_division=0
    )
)

print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Save the trained model
MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

joblib.dump(model, MODEL_PATH)

print("\n========== TRAINING COMPLETED ==========")
print(f"Model saved to: {MODEL_PATH}")
print("Note: This model was trained on synthetic data.")