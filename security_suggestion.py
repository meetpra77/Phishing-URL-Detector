# =================================================
# SMART SECURITY SUGGESTIONS
# =================================================

st.markdown("## 💡 Smart Security Suggestions")

suggestions = []

if feature_dict["has_https"] == 0:
    suggestions.append(
        "🔒 Use HTTPS websites whenever possible."
    )

if feature_dict["has_ip"] == 1:
    suggestions.append(
        "🌐 Avoid entering sensitive information on websites accessed directly by an IP address."
    )

if feature_dict["has_at"] == 1:
    suggestions.append(
        "⚠️ The URL contains '@'. Verify the real destination domain carefully."
    )

if feature_dict["url_length"] > 100:
    suggestions.append(
        "📏 The URL is unusually long. Verify the complete URL before opening it."
    )

if feature_dict["hyphen_count"] > 2:
    suggestions.append(
        "🔎 The URL contains multiple hyphens. Check the domain spelling carefully."
    )

if feature_dict["dot_count"] > 3:
    suggestions.append(
        "🔎 The URL contains several subdomains. Make sure the main domain is trusted."
    )

if prediction == 1:
    suggestions.append(
        "🚨 Do not enter passwords, OTPs, banking details, or other sensitive information until the URL is verified."
    )
else:
    suggestions.append(
        "✅ The model considers this URL likely legitimate, but always verify the domain before sharing sensitive information."
    )

for suggestion in suggestions:
    st.info(suggestion)