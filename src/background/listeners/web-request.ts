import global from '@background/global';

function handleBeforeRequest(details: chrome.webRequest.WebRequestBodyDetails) {
    if (details.tabId === chrome.tabs.TAB_ID_NONE) {
        // The request does not correspond to any tab.
        return;
    }

    const tab = global.tabs[details.tabId];
    // The tab can be removed already if the request comes after the tab is closed.
    if (tab != undefined) {
        return tab.handleBeforeRequest(details);
    }
}

function handleHeadersReceived(details: chrome.webRequest.WebResponseHeadersDetails) {
    if (details.tabId === chrome.tabs.TAB_ID_NONE) {
        // The request does not correspond to any tab.
        return;
    }

    const tab = global.tabs[details.tabId];
    // The tab can be removed already if the response comes after the tab is closed.
    if (tab != undefined) {
        return tab.handleHeadersReceived(details);
    }
}

export default {
    handleBeforeRequest,
    handleHeadersReceived,
};
