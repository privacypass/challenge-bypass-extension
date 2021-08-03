import tabs       from '@background/listeners/tabs';
import webRequest from '@background/listeners/web-request';

chrome.tabs.onCreated.addListener(
    tabs.handleCreated,
);

chrome.tabs.onReplaced.addListener(
    tabs.handleReplaced,
);

chrome.tabs.onRemoved.addListener(
    tabs.handleRemoved,
);

chrome.webRequest.onBeforeRequest.addListener(
    webRequest.handleBeforeRequest,
    {urls: ['<all_urls>']},
    ['requestBody', 'blocking'],
);

chrome.webRequest.onBeforeSendHeaders.addListener(
    webRequest.handleBeforeSendHeaders,
    {urls: ['<all_urls>']},
    ['requestHeaders', 'blocking'],
);

chrome.webRequest.onHeadersReceived.addListener(
    webRequest.handleHeadersReceived,
    {urls: ['<all_urls>']},
    ['responseHeaders', 'blocking'],
);
