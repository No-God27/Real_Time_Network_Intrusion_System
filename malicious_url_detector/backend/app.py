from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import os
import re
import requests
from datetime import datetime

app = Flask(__name__)
CORS(app)

# ===== YOUR CREDENTIALS =====
TELEGRAM_TOKEN = '7031540890:AAHrh5Zk4ifjrnTr-qP0ky3v0knv4GoUjsA'
ADMIN_CHAT_ID = '5609482527'
# ============================

TELEGRAM_API = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage'

MODEL_DIRECTORY = './model'
tfid_vectorizer = joblib.load(os.path.join(MODEL_DIRECTORY, 'tfid_vectorizer.pkl'))
url_classifier = joblib.load(os.path.join(MODEL_DIRECTORY, 'url_logistic_regression_classifier.pkl'))


def clean_url(url):
    return re.sub(r'^https?:\/\/(www\.)?', '', url).rstrip('/')


def send_admin_alert(url, probability):
    """Send alert to your phone via Telegram"""
    message = (
        f"🚨 MALICIOUS URL DETECTED!\n"
        f"▸ URL: {url}\n"
        f"▸ Confidence: {probability:.2%}\n"
        f"▸ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    requests.post(TELEGRAM_API, json={
        'chat_id': ADMIN_CHAT_ID,
        'text': message,
        'parse_mode': 'Markdown'
    })


@app.route('/check-url', methods=['POST'])
def check_url():
    try:
        data = request.json
        raw_url = data.get('url', '')
        cleaned_url = clean_url(raw_url)

        example_vectorized = tfid_vectorizer.transform([cleaned_url])
        prediction = url_classifier.predict(example_vectorized)
        probability = url_classifier.predict_proba(example_vectorized)

        if prediction[0] == 1:
            send_admin_alert(cleaned_url, probability[0][1])
            return jsonify({
                'status': 'malicious',
                'confidence': float(probability[0][1])
            })

        return jsonify({'status': 'safe'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(port=5000)