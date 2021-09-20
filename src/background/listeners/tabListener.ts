import { Tab } from '../tab';

export function handleActivated(activeInfo: { tabId: number; windowId: number }) {
    const activeTab = window.TABS.get(window.ACTIVE_TAB_ID);
    if (activeTab !== undefined) {
        activeTab.handleDeactivated();
    }

    window.ACTIVE_TAB_ID = activeInfo.tabId;
    window.TABS.get(activeInfo.tabId)?.handleActivated();
}

export function handleCreated(tab: chrome.tabs.Tab): void {
    if (tab.id !== undefined && tab.id !== chrome.tabs.TAB_ID_NONE) {
        window.TABS.set(tab.id, new Tab(tab.id));
    }
}

export function handleRemoved(tabId: number, _removeInfo: chrome.tabs.TabRemoveInfo): void {
    window.TABS.delete(tabId);
}

export function handleReplaced(addedTabId: number, removedTabId: number): void {
    window.TABS.delete(removedTabId);
    window.TABS.set(addedTabId, new Tab(addedTabId));
}
