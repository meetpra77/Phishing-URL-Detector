import pandas as pd
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

# Load dataset
data = pd.read_csv("phishing_dataset.csv")


# Extract features from URL
def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    features = {
        "url_length": len(url),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "slash_count": url.count("/"),
        "digit_count": sum(c.isdigit() for c in url),
        "special_char_count": sum(not c.isalnum() for c in url),
        "has_https": int(parsed.scheme == "https"),
        "has_at": int("@" in url),
        "has_ip": int(
            all(part.isdigit() for part in hostname.split("."))
            and hostname.count(".") == 3
        )
    }

    return features


# Create features
X = pd.DataFrame(
    data["url"].apply(extract_features).tolist()
)

# Target labels
y = data["label"]


# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


# Create Random Forest model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)


# Train model
model.fit(X_train, y_train)


# Make predictions
prediction = model.predict(X_test)


# Calculate accuracy
accuracy = accuracy_score(y_test, prediction)

print("Model Training Completed!")
print("Accuracy:", accuracy)


# Save trained model
joblib.dump(model, "phishing_model.pkl")

print("Model saved as phishing_model.pkl")