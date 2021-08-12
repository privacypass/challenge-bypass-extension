import { handleBeforeRequest, handleHeadersReceived } from './listeners/webRequestListener';
import { handleCreated, handleRemoved, handleReplaced } from './listeners/tabListener';

import { Tab } from './tab';

/* Listeners for navigator */

declare global {
    interface Window {
        TABS: Map<number, Tab>;
    }
}

window.TABS = new Map<number, Tab>();

/* Listeners for navigator */

chrome.tabs.onCreated.addListener(handleCreated);

chrome.tabs.onReplaced.addListener(handleReplaced);

chrome.tabs.onRemoved.addListener(handleRemoved);

// Loads all the existings tabs.
chrome.tabs.query({}, function (existingTabs: chrome.tabs.Tab[]) {
    existingTabs.forEach((tab) => {
        if (tab.id === undefined) {
            throw new Error('tab undefined');
        }
        window.TABS.set(tab.id, new Tab(tab.id));
    });
});

chrome.webRequest.onBeforeRequest.addListener(handleBeforeRequest, { urls: ['<all_urls>'] }, [
    'requestBody',
    'blocking',
]);

chrome.webRequest.onHeadersReceived.addListener(handleHeadersReceived, { urls: ['<all_urls>'] }, [
    'responseHeaders',
    'blocking',
]);
