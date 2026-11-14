# Phishing Website Detector

A Chrome extension that detects phishing websites in real time using a **Gradient Boosting ML model** trained on 11,430 real URLs with 87 features.

---

## How It Works

```
You open a website in Chrome
  → Extension captures the URL
  → Sends it to Flask backend (POST /predict)
  → 87 features extracted from the URL
  → Gradient Boosting model predicts phishing probability
  → Result shown: SAFE / SUSPICIOUS / PHISHING with risk score
```

---

## Project Structure

```
chrome extension/
├── start.bat                          ← Run this to set up and start everything
├── dataset_phishing.csv               ← Original dataset (place here)
└── PhishingWebsiteDetector/
    ├── backend/
    │   ├── app.py                     ← Flask REST API
    │   ├── feature_extractor.py       ← Extracts 87 URL features (runtime)
    │   ├── requirements.txt           ← Python dependencies
    │   └── model/
    │       ├── phishing_model.pkl     ← Trained model (auto-generated)
    │       └── model_meta.json        ← Model metadata (auto-generated)
    ├── extension/
    │   ├── manifest.json              ← Chrome extension config
    │   ├── popup.html                 ← Extension UI
    │   ├── popup.css                  ← Extension styles
    │   ├── popup.js                   ← Extension logic
    │   ├── background.js              ← Service worker
    │   └── icons/
    │       ├── icon16.png
    │       ├── icon48.png
    │       └── icon128.png
    └── ml/
        ├── dataset_phishing.csv       ← Dataset copy (auto-copied by start.bat)
        ├── preprocess.py              ← Cleans dataset → cleaned_dataset.csv
        ├── train_model.py             ← Trains Gradient Boosting model
        ├── feature_extractor.py       ← Same feature logic as backend
        └── cleaned_dataset.csv        ← Auto-generated after preprocessing
```

---

## Dataset

**File:** `dataset_phishing.csv`  
**Source:** [Kaggle — Web Page Phishing Detection Dataset](https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset)  
**Size:** 11,430 URLs (5,715 legitimate + 5,715 phishing) — perfectly balanced  
**Features:** 87 pre-computed URL and page features  
**Label column:** `status` → `legitimate` / `phishing`

Place the downloaded file at:
```
C:\Users\MUSKAN\OneDrive\Desktop\chrome extension\dataset_phishing.csv
```

---

## ML Model

| Property | Value |
|---|---|
| Algorithm | Gradient Boosting Classifier |
| Features | 87 (URL structure, domain, page-level) |
| Dataset size | 11,430 URLs |
| Train / Test split | 80% / 20% |
| Expected Accuracy | ~97–98% |

**Why Gradient Boosting?**  
This dataset has 87 pre-computed numerical features with complex non-linear relationships. Gradient Boosting handles this better than Random Forest — it builds trees sequentially, each correcting the previous one's errors, giving higher accuracy on tabular data.

---

## Quick Start

### Option 1 — One Click (Recommended)

Double-click `start.bat`

It will automatically:
1. Create Python virtual environment
2. Install all dependencies
3. Preprocess the dataset
4. Train the ML model
5. Start the Flask API

### Option 2 — Manual Setup

```powershell
cd "C:\Users\MUSKAN\OneDrive\Desktop\chrome extension\PhishingWebsiteDetector"

# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# Install dependencies
pip install flask flask-cors scikit-learn joblib numpy pandas

# Preprocess dataset
python ml\preprocess.py

# Train model
python ml\train_model.py

# Start Flask API
python backend\app.py
```

---

## Install Chrome Extension

1. Open Chrome → go to `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the `PhishingWebsiteDetector/extension/` folder
5. Extension icon appears in Chrome toolbar

---

## Using the Extension

1. Make sure Flask API is running (`start.bat` or `python backend\app.py`)
2. Open any website in Chrome
3. Click the 🛡️ extension icon
4. Click **Scan This Website**
5. See result: **SAFE** / **SUSPICIOUS** / **PHISHING**

---

## API Reference

### POST /predict

**Request:**
```json
{ "url": "https://example.com" }
```

**Response:**
```json
{
  "prediction": "safe",
  "risk_score": 12.5,
  "confidence": 87.5,
  "domain": "example.com",
  "message": "No major suspicious URL patterns were detected.",
  "recommendation": "You can browse normally, but always stay alert.",
  "reasons": []
}
```

### GET /health

```json
{ "status": "ok", "model_loaded": true }
```

---

## Risk Classification

| Phishing Probability | Result |
|---|---|
| < 35% | ✅ SAFE |
| 35% – 65% | ⚠️ SUSPICIOUS |
| > 65% | 🚨 PHISHING |

---

## Troubleshooting

**"Cannot reach the server" in extension**
- Make sure Flask is running: `python backend\app.py`
- Check port 5000 is free: `netstat -ano | findstr :5000`
- Kill if occupied: `taskkill /F /PID <PID>`

**"Model not found" error**
- Run training: `python ml\train_model.py`
- Make sure `cleaned_dataset.csv` exists (run `preprocess.py` first)

**`preprocess.py` fails**
- Make sure `dataset_phishing.csv` is in the `ml/` folder
- Check the file has `url` and `status` columns

**Extension not loading in Chrome**
- Make sure Developer Mode is ON
- Make sure you selected the `extension/` folder, not the project root

**pip install fails**
- Try: `pip install flask flask-cors scikit-learn joblib numpy pandas --only-binary=:all:`

---

## Privacy

- Only reads the current tab URL
- No URLs stored permanently
- No browsing history collected
- All processing runs locally on your machine
- No external API calls
