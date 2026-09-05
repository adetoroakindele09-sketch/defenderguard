import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

print("Loading dataset...")

# Load only a small sample (5000 rows)
df = pd.read_parquet("dataset/Obfuscated-MalMem2022.parquet").sample(
    n=5000,
    random_state=42
)

print("Dataset loaded successfully.")
print(df.shape)

print(df.columns.tolist())

# -----------------------------
# Detect target column
# -----------------------------
possible_targets = [
    "Class",
    "class",
    "Label",
    "label",
    "Category",
    "category",
    "Malware",
    "malware"
]

target = None

for col in possible_targets:
    if col in df.columns:
        target = col
        break

if target is None:
    print("Target column not found.")
    exit()

print("Target column:", target)

# -----------------------------
# Prepare data
# -----------------------------
X = df.drop(columns=[target]).copy()
y = df[target]

# Remove text columns to reduce memory usage
X = X.select_dtypes(include=["number"])

print("Number of features:", X.shape[1])

# -----------------------------
# Train/Test Split
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# -----------------------------
# Train Model
# -----------------------------
print("Training model...")

model = RandomForestClassifier(
    n_estimators=50,
    max_depth=15,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# -----------------------------
# Evaluate
# -----------------------------
predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("Accuracy:", accuracy)

# -----------------------------
# Save Model
# -----------------------------
joblib.dump(model, "malware_model.pkl")

print("Model saved successfully as malware_model.pkl")