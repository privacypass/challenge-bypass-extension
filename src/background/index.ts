import {
    handleActivated,
    handleCreated,
    handleRemoved,
    handleReplaced,
} from './listeners/tabListener';
import {
    handleBeforeRequest,
    handleBeforeSendHeaders,
    handleHeadersReceived,
} from './listeners/webRequestListener';

import { Tab } from './tab';

/* Listeners for navigator */

declare global {
    interface Window {
        ACTIVE_TAB_ID: number;
        TABS: Map<number, Tab>;
    }
}

declare let browser: unknown;

window.ACTIVE_TAB_ID = chrome.tabs.TAB_ID_NONE;
window.TABS = new Map<number, Tab>();

const BROWSERS = {
    CHROME: 'Chrome',
    FIREFOX: 'Firefox',
    EDGE: 'Edge',
} as const;
type BROWSERS = typeof BROWSERS[keyof typeof BROWSERS];

function getBrowser(): BROWSERS {
    if (typeof chrome !== 'undefined') {
        if (typeof browser !== 'undefined') {
            return BROWSERS.FIREFOX;
        }
        return BROWSERS.CHROME;
    }
    return BROWSERS.EDGE;
}

/* Listeners for navigator */

chrome.tabs.onActivated.addListener(handleActivated);

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

// Finds which tab is currently active.
chrome.tabs.query({ active: true, currentWindow: true }, function (tabs: chrome.tabs.Tab[]) {
    const [tab] = tabs;
    if (tab !== undefined && tab.id !== undefined) {
        window.ACTIVE_TAB_ID = tab.id;
    }
});

chrome.webRequest.onBeforeRequest.addListener(handleBeforeRequest, { urls: ['<all_urls>'] }, [
    'requestBody',
    'blocking',
]);

const extraInfos = ['requestHeaders', 'blocking'];
if (getBrowser() === BROWSERS.CHROME) {
    extraInfos.push('extraHeaders');
}
chrome.webRequest.onBeforeSendHeaders.addListener(
    handleBeforeSendHeaders,
    { urls: ['<all_urls>'] },
    extraInfos,
);

chrome.webRequest.onHeadersReceived.addListener(handleHeadersReceived, { urls: ['<all_urls>'] }, [
    'responseHeaders',
    'blocking',
]);

// TODO Using Message passing is dirty. It's better to use chrome.storage for sharing
// common data between the popup and the background script.
chrome.runtime.onMessage.addListener((request, _sender, sendResponse) => {
    if (request.clear === true) {
        window.localStorage.clear();

        // Update the browser action icon after clearing the tokens.
        const activeTab = window.TABS.get(window.ACTIVE_TAB_ID);
        if (activeTab !== undefined) {
            activeTab.forceUpdateIcon();
        }
        return;
    }

    if (request.key !== undefined && typeof request.key === 'string') {
        sendResponse(window.localStorage.getItem(request.key));
    }
});

// TODO It's better to move this to the provider class. Let's figure out how to do it later.
// Removes cookies for captcha.website to enable getting more tokens in the future.
chrome.cookies.onChanged.addListener((changeInfo) => {
    if (
        !changeInfo.removed &&
        changeInfo.cookie.domain === '.captcha.website' &&
        changeInfo.cookie.name === 'cf_clearance'
    ) {
        chrome.cookies.remove({ url: 'https://captcha.website', name: 'cf_clearance' });
    }
});
