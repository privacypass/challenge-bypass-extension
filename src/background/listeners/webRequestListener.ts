export function handleBeforeRequest(
    details: chrome.webRequest.WebRequestBodyDetails,
): chrome.webRequest.BlockingResponse | void {
    if (details.tabId === chrome.tabs.TAB_ID_NONE) {
        // The request does not correspond to any tab.
        return;
    }

    const tab = window.TABS.get(details.tabId);
    // The tab can be removed already if the request comes after the tab is closed.
    return tab?.handleBeforeRequest(details);
}

export function handleBeforeSendHeaders(
    details: chrome.webRequest.WebRequestHeadersDetails,
): chrome.webRequest.BlockingResponse | void {
    if (details.tabId === chrome.tabs.TAB_ID_NONE) {
        // The request does not correspond to any tab.
        return;
    }

    const tab = window.TABS.get(details.tabId);
    // The tab can be removed already if the request comes after the tab is closed.
    return tab?.handleBeforeSendHeaders(details);
}

export function handleHeadersReceived(
    details: chrome.webRequest.WebResponseHeadersDetails,
): chrome.webRequest.BlockingResponse | void {
    if (details.tabId === chrome.tabs.TAB_ID_NONE) {
        // The request does not correspond to any tab.
        return;
    }

    const tab = window.TABS.get(details.tabId);
    // The tab can be removed already if the response comes after the tab is closed.
    return tab?.handleHeadersReceived(details);
}
