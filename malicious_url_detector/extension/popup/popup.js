document.addEventListener('DOMContentLoaded', function() {
    // Check current tab's URL when popup opens
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        const currentUrl = tabs[0].url;
        checkUrl(currentUrl, 'current');
    });

    // Manual check handler
    document.getElementById('checkButton').addEventListener('click', function() {
        const manualUrl = document.getElementById('urlInput').value;
        if (manualUrl) {
            checkUrl(manualUrl, 'manual');
        }
    });
});

function checkUrl(url, type) {
    showLoading();
    
    fetch('http://localhost:5000/check-url', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url }),
    })
    .then(response => response.json())
    .then(data => {
        updateUI(data, type);
        hideLoading();
    })
    .catch(error => {
        console.error('Error:', error);
        hideLoading();
        showError();
    });
}

function updateUI(data, type) {
    const statusClass = data.result === 'Malicious' ? 'malicious' : 'benign';
    const probability = (data.probability[0][1] * 100).toFixed(2) + '%';

    if (type === 'current') {
        document.getElementById('currentStatusText').textContent = data.result;
        document.getElementById('currentStatusText').className = statusClass;
        document.getElementById('currentProbability').textContent = `Confidence: ${probability}`;
    } else {
        document.getElementById('manualStatusText').textContent = data.result;
        document.getElementById('manualStatusText').className = statusClass;
        document.getElementById('manualProbability').textContent = `Confidence: ${probability}`;
    }
}

function showLoading() {
    document.getElementById('loading').classList.remove('hidden');
}

function hideLoading() {
    document.getElementById('loading').classList.add('hidden');
}

function showError() {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error';
    errorDiv.textContent = 'Error checking URL. Please try again.';
    document.body.appendChild(errorDiv);
    setTimeout(() => errorDiv.remove(), 3000);
}