import streamlit as st
import pandas as pd
from urllib.parse import urlparse
import joblib

# Load trained model
model = joblib.load("phishing_model.pkl")


# Extract URL features
def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    return {
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


# Page settings
st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🔐"
)

st.title("🔐 Phishing URL Detector")
st.write("Enter a URL to check the ML model prediction.")


# URL input
url = st.text_input(
    "Enter URL:",
    placeholder="https://example.com"
)


# Check button
if st.button("🔍 Check URL"):

    if not url.strip():
        st.error("Please enter a URL.")

    else:
        url = url.strip()

        # Add http if scheme is missing
        if not urlparse(url).scheme:
            url = "http://" + url

        # Extract features
        features = pd.DataFrame([
            extract_features(url)
        ])

        # Prediction
        prediction = int(model.predict(features)[0])

        # Confidence
        if hasattr(model, "predict_proba"):
            confidence = (
                float(model.predict_proba(features)[0].max()) * 100
            )
        else:
            confidence = None

        # Show result
        if prediction == 1:
            st.error("🚨 PHISHING URL")
        else:
            st.success("✅ LEGITIMATE URL")

        if confidence is not None:
            st.write(f"Model confidence: {confidence:.1f}%")

        st.caption(
            "Demo model only. Do not use this prediction as a definitive security verdict."
        )