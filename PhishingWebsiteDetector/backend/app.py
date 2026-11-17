"""
Flask REST API for phishing URL detection.
POST /predict  { "url": "https://example.com" }
GET  /health
"""

import re
import joblib
import numpy as np
from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse

from feature_extractor import extract_features, FEATURE_COLS

PORT       = 5000
MODEL_PATH = Path(__file__).parent / "model" / "phishing_model.pkl"
META_PATH  = Path(__file__).parent / "model" / "model_meta.json"

# Risk thresholds (phishing probability %)
THRESHOLD_SAFE       = 50
THRESHOLD_SUSPICIOUS = 75

MESSAGES = {
    "safe":       "No major suspicious URL patterns were detected.",
    "suspicious": "Some suspicious characteristics detected. Avoid entering sensitive information.",
    "phishing":   "This website may be attempting to steal your information. Do NOT enter any credentials.",
}
RECOMMENDATIONS = {
    "safe":       "You can browse normally, but always stay alert.",
    "suspicious": "Do not enter passwords, OTPs, or payment details on this page.",
    "phishing":   "Leave this website immediately. Do not enter any credentials or personal data.",
}

WHITELIST = {
    "google.com", "youtube.com", "facebook.com", "twitter.com", "instagram.com",
    "linkedin.com", "github.com", "stackoverflow.com", "wikipedia.org", "amazon.com",
    "microsoft.com", "apple.com", "netflix.com", "reddit.com", "yahoo.com",
    "bing.com", "dropbox.com", "spotify.com", "adobe.com", "zoom.us",
    "slack.com", "notion.so", "medium.com", "paypal.com", "stripe.com",
    "shopify.com", "ebay.com", "whatsapp.com", "telegram.org",
    # Indian & common sites
    "flipkart.com", "myntra.com", "swiggy.com", "zomato.com", "paytm.com",
    "phonepe.com", "gpay.com", "naukri.com", "irctc.co.in", "sbi.co.in",
    "hdfcbank.com", "icicibank.com", "axisbank.com", "kotak.com",
    "canara.bank", "pnbindia.in", "upi.com", "npci.org.in",
    # Dev & education
    "geeksforgeeks.org", "w3schools.com", "coursera.org", "udemy.com",
    "leetcode.com", "hackerrank.com", "kaggle.com", "npmjs.com",
    "pypi.org", "docs.python.org", "developer.mozilla.org",
    # Google subservices
    "gmail.com", "drive.google.com", "docs.google.com", "maps.google.com",
    "play.google.com", "cloud.google.com",
    # Microsoft
    "office.com", "live.com", "outlook.com", "azure.com", "visualstudio.com",
    # Others
    "cloudflare.com", "aws.amazon.com", "twitch.tv", "discord.com",
    "figma.com", "canva.com", "wordpress.com", "blogger.com",
    # AI tools
    "chatgpt.com", "openai.com", "claude.ai", "anthropic.com",
    "gemini.google.com", "copilot.microsoft.com", "perplexity.ai",
    "aistudio.google.com", "huggingface.co", "replicate.com",
    "mistral.ai", "cohere.com", "groq.com",
    # Test/demo domains
    "example.com", "example.org", "example.net", "test.com", "localhost",
    # Education domains (.edu sites)
    "kent.edu", "mit.edu", "stanford.edu", "harvard.edu", "berkeley.edu",
    "cmu.edu", "iit.ac.in", "iitb.ac.in", "iitd.ac.in", "du.ac.in",
    "amity.edu", "vit.ac.in", "bits-pilani.ac.in", "nptel.ac.in",
    # Government domains
    "gov.in", "nic.in", "india.gov.in", "mca.gov.in", "incometax.gov.in",
}

app    = Flask(__name__)
CORS(app)
_model = None


TRUSTED_TLDS = {"edu", "gov", "ac.in", "gov.in", "mil", "ac.uk", "edu.in"}


def is_trusted_tld(hostname: str) -> bool:
    for tld in TRUSTED_TLDS:
        if hostname.endswith("." + tld) or hostname == tld:
            return True
    return False


def load_model():
    global _model
    if _model is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError("Model not found. Run: python ml/train_model.py")
        _model = joblib.load(MODEL_PATH)
    return _model


def get_root_domain(hostname: str) -> str:
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def validate_url(url: str):
    if not url or not url.strip():
        return False, "URL is empty."
    if len(url) > 2048:
        return False, "URL is too long."
    blocked = ("chrome://", "chrome-extension://", "about:", "file://", "data:", "javascript:")
    if any(url.lower().startswith(s) for s in blocked):
        return False, "This page type cannot be analyzed."
    if not re.match(r"^https?://", url, re.IGNORECASE):
        return False, "Only HTTP and HTTPS URLs are supported."
    return True, None


def classify(prob: float) -> str:
    score = prob * 100
    if score < THRESHOLD_SAFE:
        return "safe"
    if score < THRESHOLD_SUSPICIOUS:
        return "suspicious"
    return "phishing"


@app.route("/health", methods=["GET"])
def health():
    try:
        load_model()
        return jsonify({"status": "ok", "model_loaded": True}), 200
    except FileNotFoundError as e:
        return jsonify({"status": "error", "message": str(e)}), 503


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON body."}), 400

    url = data.get("url", "")
    valid, err = validate_url(url)
    if not valid:
        return jsonify({"error": err}), 422

    try:
        model = load_model()
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 503

    # Whitelist check — trusted domains always safe
    parsed   = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    root     = get_root_domain(hostname)
    if root in WHITELIST or is_trusted_tld(hostname):
        return jsonify({
            "prediction":     "safe",
            "risk_score":     5.0,
            "confidence":     95.0,
            "domain":         hostname,
            "message":        MESSAGES["safe"],
            "recommendation": RECOMMENDATIONS["safe"],
            "reasons":        ["trusted domain"],
        }), 200

    features = np.array(extract_features(url)).reshape(1, -1)
    try:
        proba   = model.predict_proba(features)[0]
        ml_prob = float(proba[1]) if len(proba) > 1 else float(model.predict(features)[0])
    except Exception as e:
        return jsonify({"error": f"Prediction failed: {str(e)}"}), 500

    classification = classify(ml_prob)
    risk_score     = round(ml_prob * 100, 1)

    return jsonify({
        "prediction":     classification,
        "risk_score":     risk_score,
        "confidence":     round(100 - risk_score, 1) if classification == "safe" else round(risk_score, 1),
        "domain":         hostname or url,
        "message":        MESSAGES[classification],
        "recommendation": RECOMMENDATIONS[classification],
        "reasons":        [],
    }), 200


@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Endpoint not found."}), 404

@app.errorhandler(405)
def method_not_allowed(_):
    return jsonify({"error": "Method not allowed."}), 405


if __name__ == "__main__":
    print(f"Starting Phishing Detector API on port {PORT}...")
    try:
        load_model()
        print("Model loaded successfully.")
    except FileNotFoundError as e:
        print(f"[WARNING] {e}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
