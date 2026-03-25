# Phishing Detection using NLP

# Phishing & Scam Detector

An AI-powered browser extension that detects phishing emails in Gmail using NLP and a fine-tuned DistilBERT model, inspired by Bitdefender Scamio.

---

## Project Overview

This project is a full-stack AI system consisting of:
- A Chrome browser extension that reads emails from Gmail
- A Python FastAPI backend that runs NLP analysis
- A fine-tuned DistilBERT model trained on real phishing datasets
- Supporting modules for preprocessing, URL analysis, and model training

---

## Project Structure

```
phishing-extension/
│
├── extension/                  # Chrome Extension (Frontend)
│   ├── manifest.json           # Extension config and permissions
│   ├── content.js              # Reads Gmail DOM, extracts email data
│   ├── popup.html              # Extension popup UI
│   ├── popup.js                # Popup logic, API calls, result rendering
│   └── styles.css              # Banner and popup styles
│
└── backend/                    # Python Backend
    ├── main.py                 # FastAPI app, /analyze and /health endpoints
    ├── model.py                # DistilBERT inference pipeline
    ├── preprocessor.py         # Text cleaning, urgency scoring, NER
    ├── url_analyzer.py         # URL feature extraction and risk scoring
    ├── train.py          # Model training script
    └── requirements.txt        # Python dependencies
```

---

## How It Works

1. User opens an email in Gmail
2. The Chrome extension reads the email subject, body, sender, and URLs from the Gmail DOM
3. The extension sends this data to the local FastAPI backend
4. The backend runs the full NLP pipeline:
   - Text preprocessing (cleaning, tokenization, lemmatization)
   - Urgency and manipulation scoring
   - Named Entity Recognition for brand spoofing detection
   - URL risk analysis (lookalike domains, suspicious TLDs, redirects)
   - DistilBERT classification
5. The backend returns a verdict (PHISHING or LEGIT), confidence score, and reasons
6. The extension displays a banner inside Gmail with the result

---

## Tech Stack

| Layer | Technology |
|---|---|
| Browser Extension | JavaScript, Chrome Extensions API (Manifest V3) |
| Backend Framework | Python, FastAPI, Uvicorn |
| NLP Model | DistilBERT (fine-tuned), HuggingFace Transformers |
| Classical NLP | NLTK, scikit-learn, TF-IDF |
| Named Entity Recognition | spaCy (en_core_web_sm) |
| URL Analysis | tldextract, urllib |
| Training Datasets | SMS Spam Collection, SpamAssassin, Enron Spam |

---

## Setup Instructions

### 1. Clone the repository

```bash
git clone https://github.com/your-username/phishing-detector.git
cd phishing-detector
```

### 2. Set up the Python backend

```bash
cd backend
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### 3. Train the model

Run training locally or on Google Colab (recommended — free GPU):

```bash
python train_model.py
```

This will:
- Automatically download the SMS Spam, SpamAssassin, and Enron datasets
- Train a TF-IDF baseline and a fine-tuned DistilBERT model
- Save the trained model to ./trained_model/

On Google Colab, training takes approximately 30 minutes on a free T4 GPU.

### 4. Start the backend server

```bash
uvicorn main:app --reload
```

The API will be available at http://localhost:8000.
You can verify it is running by visiting http://localhost:8000/health.

### 5. Load the Chrome extension

1. Open Chrome and navigate to chrome://extensions
2. Enable Developer Mode (toggle in the top right)
3. Click Load unpacked
4. Select the /extension folder from this project
5. The extension icon will appear in your Chrome toolbar

### 6. Test it

1. Open Gmail in Chrome
2. Open any email
3. Click the extension icon and press Scan Current Email
4. The result will appear both in the popup and as a banner inside Gmail

---

## Installation Commands (Quick Reference)

```bash
# All Python dependencies
pip install -r requirements.txt

# Individual packages
pip install fastapi uvicorn
pip install transformers torch
pip install spacy nltk scikit-learn
pip install tldextract requests
pip install datasets evaluate accelerate

# spaCy English model (required separately)
python -m spacy download en_core_web_sm
```

---

## API Endpoints

### POST /analyze
Accepts email data and returns a phishing verdict.

Request body:
```json
{
  "subject": "Urgent: Your account has been suspended",
  "body": "Click here to verify your account immediately...",
  "sender": "support@paypa1-secure.com",
  "urls": ["http://paypa1-secure.com/verify"]
}
```

Response:
```json
{
  "label": "PHISHING",
  "confidence": 0.976,
  "reasons": [
    "Urgency/fear language detected",
    "Impersonates PayPal (sent from paypa1-secure.com)",
    "Lookalike domain detected: paypa1 → paypal",
    "Suspicious TLD: .com with brand mismatch"
  ]
}
```

### GET /health
Returns 200 OK if the backend is running. Used by the extension to check connectivity.

---

## Datasets

| Dataset | Size | Source |
|---|---|---|
| SMS Spam Collection | 5,574 messages | HuggingFace: ucirvine/sms_spam |
| SpamAssassin | ~6,000 emails | HuggingFace: talby/spamassassin |
| Enron Spam | ~33,000 emails | HuggingFace: SetFit/enron_spam |

All datasets are downloaded automatically by train_model.py. No manual setup required.

---

## Model Performance

After fine-tuning on the combined dataset:

| Metric | TF-IDF Baseline | DistilBERT |
|---|---|---|
| Accuracy | ~96% | ~98.5% |
| F1 Score | ~95% | ~98.3% |
| ROC-AUC | ~99% | ~99.7% |

---

## Limitations

- The Gmail DOM selectors in content.js may break if Google updates the Gmail UI
- The backend must be running locally for the extension to work
- The extension currently supports Gmail only (Outlook support can be added)
- The model should be periodically retrained as new phishing patterns emerge

---

## Acknowledgements

- Inspired by Bitdefender Scamio
- Built with HuggingFace Transformers and the spaCy NLP library
- Training data from the UCI ML Repository, Apache SpamAssassin, and the Enron dataset

---

## License

MIT License. Free to use for educational and research purposes.
