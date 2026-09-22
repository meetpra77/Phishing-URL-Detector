import streamlit as st
import pandas as pd
from urllib.parse import urlparse
import joblib
import re

# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="PhishGuard | URL Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =========================================================
# LOAD MODEL
# =========================================================

@st.cache_resource
def load_model():
    return joblib.load("phishing_model.pkl")

model = load_model()


# =========================================================
# CUSTOM CSS
# =========================================================

st.markdown("""
<style>

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background:
        radial-gradient(circle at 10% 10%, rgba(0, 255, 170, 0.08), transparent 25%),
        radial-gradient(circle at 90% 20%, rgba(80, 120, 255, 0.10), transparent 25%),
        #07111f;
    color: #f5f7fa;
}

/* Main container */
.block-container {
    max-width: 1200px;
    padding-top: 2rem;
}

/* Header */
.hero {
    padding: 30px;
    border-radius: 24px;
    background: linear-gradient(
        135deg,
        rgba(14, 29, 48, 0.95),
        rgba(8, 20, 35, 0.95)
    );
    border: 1px solid rgba(0, 255, 170, 0.18);
    box-shadow: 0 20px 60px rgba(0,0,0,0.35);
    margin-bottom: 25px;
}

.hero-title {
    font-size: 42px;
    font-weight: 800;
    margin: 0;
    color: #ffffff;
}

.hero-subtitle {
    color: #9caec4;
    font-size: 16px;
    margin-top: 8px;
}

.badge {
    display: inline-block;
    padding: 7px 14px;
    border-radius: 30px;
    background: rgba(0,255,170,0.10);
    color: #00ffaa;
    border: 1px solid rgba(0,255,170,0.25);
    font-size: 13px;
    font-weight: 700;
}

/* Cards */
.card {
    background: rgba(14, 29, 48, 0.85);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 18px;
    padding: 22px;
    margin-bottom: 18px;
    box-shadow: 0 12px 35px rgba(0,0,0,0.20);
}

.card-title {
    font-size: 18px;
    font-weight: 700;
    color: #ffffff;
    margin-bottom: 12px;
}

/* Metric cards */
.metric {
    background: linear-gradient(
        145deg,
        rgba(17, 34, 55, 0.95),
        rgba(9, 23, 40, 0.95)
    );
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 18px;
    padding: 20px;
    text-align: center;
    min-height: 125px;
}

.metric-icon {
    font-size: 25px;
}

.metric-value {
    font-size: 27px;
    font-weight: 800;
    color: #ffffff;
    margin-top: 6px;
}

.metric-label {
    color: #8fa3bb;
    font-size: 13px;
}

/* URL box */
.url-box {
    background: #050d18;
    border: 1px solid rgba(0,255,170,0.18);
    border-radius: 14px;
    padding: 15px 18px;
    color: #00ffaa;
    font-family: monospace;
    word-break: break-all;
}

/* Result */
.result-safe {
    background: linear-gradient(
        135deg,
        rgba(0, 180, 120, 0.18),
        rgba(0, 255, 170, 0.05)
    );
    border: 1px solid rgba(0,255,170,0.30);
    border-radius: 20px;
    padding: 25px;
}

.result-danger {
    background: linear-gradient(
        135deg,
        rgba(255, 50, 70, 0.18),
        rgba(255, 90, 70, 0.05)
    );
    border: 1px solid rgba(255,70,80,0.30);
    border-radius: 20px;
    padding: 25px;
}

.result-title {
    font-size: 28px;
    font-weight: 800;
}

/* Feature table */
.feature-good {
    color: #00ffaa;
    font-weight: 700;
}

.feature-warning {
    color: #ffd166;
    font-weight: 700;
}

.feature-danger {
    color: #ff6472;
    font-weight: 700;
}

/* Footer */
.footer {
    text-align: center;
    color: #71839a;
    padding: 30px 0 10px 0;
    font-size: 13px;
}

</style>
""", unsafe_allow_html=True)


# =========================================================
# FEATURE EXTRACTION
# =========================================================

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


# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:

    st.markdown("## 🛡️ PhishGuard")

    st.markdown("---")

    st.markdown("### 🔐 Scanner")

    st.write(
        "Machine-learning based URL analysis "
        "for phishing detection."
    )

    st.markdown("---")

    st.markdown("### 📋 Detection checks")

    st.write("✓ URL structure")
    st.write("✓ HTTPS usage")
    st.write("✓ IP address detection")
    st.write("✓ Suspicious characters")
    st.write("✓ URL length")
    st.write("✓ ML model prediction")

    st.markdown("---")

    st.caption(
        "⚠️ Demo security tool. "
        "Results should not be treated as a definitive security verdict."
    )


# =========================================================
# HERO
# =========================================================

st.markdown("""
<div class="hero">

<span class="badge">CYBER SECURITY • ML URL ANALYSIS</span>

<div class="hero-title">
🛡️ PhishGuard
</div>

<div class="hero-title" style="font-size:30px;">
Phishing URL Detector
</div>

<div class="hero-subtitle">
Analyze suspicious URLs using machine learning and URL security features.
</div>

</div>
""", unsafe_allow_html=True)


# =========================================================
# URL INPUT
# =========================================================

st.markdown("""
<div class="card">
<div class="card-title">🔍 URL Security Scanner</div>
</div>
""", unsafe_allow_html=True)

url = st.text_input(
    "Enter URL",
    placeholder="https://example.com",
    label_visibility="collapsed"
)

scan = st.button(
    "🚀  SCAN URL",
    use_container_width=True
)


# =========================================================
# SCAN
# =========================================================

if scan:

    if not url.strip():

        st.warning("⚠️ Please enter a URL before scanning.")

    else:

        url = url.strip()

        # Add scheme
        if not urlparse(url).scheme:
            url = "http://" + url

        # Extract features
        feature_dict = extract_features(url)

        features = pd.DataFrame([feature_dict])

        # Prediction
        prediction = int(model.predict(features)[0])

        # Confidence
        if hasattr(model, "predict_proba"):

            probabilities = model.predict_proba(features)[0]
            confidence = float(probabilities.max()) * 100

        else:

            confidence = None

        # =================================================
        # RESULT
        # =================================================

        st.markdown("## 📊 Security Analysis")

        st.markdown(
            f"""
            <div class="url-box">
            🔗 {url}
            </div>
            """,
            unsafe_allow_html=True
        )

        st.write("")

        if prediction == 1:

            result_title = "🚨 PHISHING URL"
            result_text = (
                "The machine-learning model classified this URL "
                "as potentially suspicious."
            )

            result_class = "result-danger"

            risk = "HIGH"
            risk_icon = "🔴"

        else:

            result_title = "✅ LEGITIMATE URL"
            result_text = (
                "The machine-learning model classified this URL "
                "as likely legitimate."
            )

            result_class = "result-safe"

            if confidence is not None and confidence >= 80:
                risk = "LOW"
                risk_icon = "🟢"
            else:
                risk = "MEDIUM"
                risk_icon = "🟡"


        st.markdown(
            f"""
            <div class="{result_class}">

            <div class="result-title">
            {result_title}
            </div>

            <p style="color:#aebed1;">
            {result_text}
            </p>

            </div>
            """,
            unsafe_allow_html=True
        )

        st.write("")

        # =================================================
        # METRICS
        # =================================================

        col1, col2, col3, col4 = st.columns(4)

        with col1:

            st.markdown(
                f"""
                <div class="metric">
                <div class="metric-icon">🎯</div>
                <div class="metric-value">
                {confidence:.1f}%
                </div>
                <div class="metric-label">
                Model Confidence
                </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with col2:

            st.markdown(
                f"""
                <div class="metric">
                <div class="metric-icon">{risk_icon}</div>
                <div class="metric-value">
                {risk}
                </div>
                <div class="metric-label">
                Risk Level
                </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with col3:

            rating = round(confidence)

            stars = min(5, max(1, round(confidence / 20)))

            star_display = "⭐" * stars

            st.markdown(
                f"""
                <div class="metric">
                <div class="metric-icon">⭐</div>
                <div class="metric-value">
                {rating}/100
                </div>
                <div class="metric-label">
                Model Rating
                </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with col4:

            length = len(url)

            st.markdown(
                f"""
                <div class="metric">
                <div class="metric-icon">🔗</div>
                <div class="metric-value">
                {length}
                </div>
                <div class="metric-label">
                URL Characters
                </div>
                </div>
                """,
                unsafe_allow_html=True
            )


        # =================================================
        # CONFIDENCE BAR
        # =================================================

        st.write("")

        st.markdown("### 📈 Model Confidence")

        st.progress(
            min(max(confidence / 100, 0.0), 1.0)
        )

        st.caption(
            f"Prediction confidence: {confidence:.1f}%"
        )


        # =================================================
        # FEATURE ANALYSIS
        # =================================================

        st.markdown("## 🔎 URL Feature Analysis")

        feature_rows = []

        feature_rows.append([
            "URL Length",
            feature_dict["url_length"],
            "Normal" if feature_dict["url_length"] < 100 else "Long"
        ])

        feature_rows.append([
            "Dot Count",
            feature_dict["dot_count"],
            "Normal" if feature_dict["dot_count"] <= 3 else "High"
        ])

        feature_rows.append([
            "Hyphen Count",
            feature_dict["hyphen_count"],
            "Normal" if feature_dict["hyphen_count"] <= 2 else "High"
        ])

        feature_rows.append([
            "Slash Count",
            feature_dict["slash_count"],
            "Normal" if feature_dict["slash_count"] <= 5 else "High"
        ])

        feature_rows.append([
            "Digit Count",
            feature_dict["digit_count"],
            "Normal" if feature_dict["digit_count"] <= 5 else "High"
        ])

        feature_rows.append([
            "Special Characters",
            feature_dict["special_char_count"],
            "Normal" if feature_dict["special_char_count"] <= 10 else "High"
        ])

        feature_rows.append([
            "HTTPS",
            "Enabled" if feature_dict["has_https"] else "Not detected",
            "Good" if feature_dict["has_https"] else "Warning"
        ])

        feature_rows.append([
            "@ Symbol",
            "Detected" if feature_dict["has_at"] else "Not detected",
            "Warning" if feature_dict["has_at"] else "Good"
        ])

        feature_rows.append([
            "IP Address",
            "Detected" if feature_dict["has_ip"] else "Not detected",
            "Warning" if feature_dict["has_ip"] else "Good"
        ])

        feature_df = pd.DataFrame(
            feature_rows,
            columns=["Security Feature", "Value", "Status"]
        )

        st.dataframe(
            feature_df,
            use_container_width=True,
            hide_index=True
        )


        # =================================================
        # SECURITY CHECKS
        # =================================================

        st.markdown("## 🛡️ Security Checks")

        c1, c2, c3 = st.columns(3)

        with c1:

            if feature_dict["has_https"]:
                st.success("🔒 HTTPS detected")
            else:
                st.warning("⚠️ HTTPS not detected")

        with c2:

            if feature_dict["has_ip"]:
                st.error("🚨 IP-based URL detected")
            else:
                st.success("🌐 Domain-based URL")

        with c3:

            if feature_dict["has_at"]:
                st.error("⚠️ @ symbol detected")
            else:
                st.success("✓ No @ symbol")


        # =================================================
        # RECOMMENDATIONS
        # =================================================

        st.markdown("## 💡 Security Recommendations")

        if prediction == 1:

            st.error(
                "🚨 Avoid opening or entering credentials into this URL "
                "until it has been independently verified."
            )

            st.write(
                "• Verify the domain manually."
            )

            st.write(
                "• Do not enter passwords or financial information."
            )

            st.write(
                "• Check the sender/source of the URL."
            )

        else:

            st.success(
                "✅ The model classified this URL as likely legitimate."
            )

            st.write(
                "• Still verify the domain before entering sensitive information."
            )

            st.write(
                "• Look for HTTPS and the correct domain name."
            )

            st.write(
                "• Do not rely on a machine-learning prediction alone."
            )


# =========================================================
# INFORMATION SECTION
# =========================================================

st.markdown("---")

with st.expander("ℹ️ About PhishGuard"):

    st.write(
        """
        PhishGuard is a demonstration machine-learning application
        designed to analyze URLs for potential phishing characteristics.

        The application extracts structural URL features and sends them
        to a trained machine-learning model for classification.
        """
    )

with st.expander("⚠️ Important Security Notice"):

    st.warning(
        """
        This application is a demonstration security tool.
        A legitimate classification does not guarantee that a website
        is safe, and a phishing classification should be independently
        verified. Do not use this tool as the only security control.
        """
    )


# =========================================================
# FOOTER
# =========================================================

st.markdown("""
<div class="footer">

🛡️ PhishGuard • Phishing URL Detector

<br>

Cyber Security • Machine Learning • URL Analysis

</div>
""", unsafe_allow_html=True)