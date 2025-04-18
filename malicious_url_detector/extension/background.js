chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.url) {
        checkAndNotify(tabId, changeInfo.url);
    }
});

chrome.tabs.onActivated.addListener((activeInfo) => {
    chrome.tabs.get(activeInfo.tabId, (tab) => {
        if (tab.url) {
            checkAndNotify(activeInfo.tabId, tab.url);
        }
    });
});

function checkAndNotify(tabId, url) {
    fetch('http://localhost:5000/check-url', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url }),
    })
    .then(response => response.json())
    .then(data => {
        if (data.result === 'Malicious') {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icon.png',
                title: '⚠️ Malicious URL Detected!',
                message: `Blocked access to ${new URL(url).hostname}`
            });
            
            // Redirect to warning page
            chrome.scripting.executeScript({
                target: { tabId: tabId },
                func: (url) => {
                    window.location.href = chrome.runtime.getURL('warning.html') + 
                                        `?url=${encodeURIComponent(url)}`;
                },
                args: [url]
            });
        }
    })
    .catch(error => console.error('Error:', error));
}