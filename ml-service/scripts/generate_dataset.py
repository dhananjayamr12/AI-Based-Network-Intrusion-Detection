import pandas as pd
import numpy as np
from pathlib import Path

# Reproducible sample data
np.random.seed(42)

# Number of network traffic records
normal_count = 1000
attack_count = 1000

# Generate normal network traffic
normal = pd.DataFrame({
    "duration": np.random.exponential(2, normal_count),
    "src_bytes": np.random.randint(100, 5000, normal_count),
    "dst_bytes": np.random.randint(100, 8000, normal_count),
    "packets": np.random.randint(2, 100, normal_count),
    "failed_connections": np.random.randint(0, 2, normal_count),
    "label": 0
})

# Generate synthetic attack traffic
attack = pd.DataFrame({
    "duration": np.random.exponential(0.5, attack_count),
    "src_bytes": np.random.randint(0, 1000, attack_count),
    "dst_bytes": np.random.randint(0, 2000, attack_count),
    "packets": np.random.randint(100, 1000, attack_count),
    "failed_connections": np.random.randint(5, 30, attack_count),
    "label": 1
})

# Combine and shuffle records
dataset = pd.concat([normal, attack], ignore_index=True)
dataset = dataset.sample(frac=1, random_state=42).reset_index(drop=True)

# Save dataset on D drive
output_path = Path("D:/AI-NIDS/datasets/synthetic_network_traffic.csv")
dataset.to_csv(output_path, index=False)

print("Synthetic dataset created successfully!")
print(f"Saved to: {output_path}")
print(f"Total records: {len(dataset)}")
print("\nLabel distribution:")
print(dataset["label"].value_counts().rename({
    0: "Normal (synthetic)",
    1: "Attack (synthetic)"
}))