import { Tab } from '../tab';

function getTab(id: number): Tab | null {
    if (id === chrome.tabs.TAB_ID_NONE) {
        // The request does not correspond to any tab.
        return null;
    }

    // The tab can be removed already if the request comes after the tab is closed.
    const tab: Tab | void = window.TABS.get(id);

    return (tab === undefined) ? null : tab;
}

export function handleBeforeRequest(
    details: chrome.webRequest.WebRequestBodyDetails,
): chrome.webRequest.BlockingResponse | void {
    const tab = getTab(details.tabId);
    if (tab === null) return;

    return tab!.handleBeforeRequest(details);
}

export function handleBeforeSendHeaders(
    details: chrome.webRequest.WebRequestHeadersDetails,
): chrome.webRequest.BlockingResponse | void {
    const tab = getTab(details.tabId);
    if (tab === null) return;

    return tab!.handleBeforeSendHeaders(details);
}

export function handleHeadersReceived(
    details: chrome.webRequest.WebResponseHeadersDetails,
): chrome.webRequest.BlockingResponse | void {
    const tab = getTab(details.tabId);
    if (tab === null) return;

    return tab!.handleHeadersReceived(details);
}

export function handleOnCompleted(
    details: chrome.webRequest.WebResponseHeadersDetails,
): void {
    const tab = getTab(details.tabId);
    if (tab === null) return;

    return tab!.handleOnCompleted(details);
}

export function handleOnErrorOccurred(
    details: chrome.webRequest.WebResponseErrorDetails,
): void {
    const tab = getTab(details.tabId);
    if (tab === null) return;

    return tab!.handleOnErrorOccurred(details);
}
