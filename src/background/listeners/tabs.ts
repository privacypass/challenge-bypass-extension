import global from '@background/global';
import Tab    from '@background/tab';

function handleActivated(activeInfo: { tabId: number, windowId: number }) {
    const activeTab = global.tabs[global.activeTabId];
    if (activeTab !== undefined) {
        activeTab.handleDeactivated();
    }

    global.activeTabId = activeInfo.tabId;
    global.tabs[activeInfo.tabId].handleActivated();
}

function handleCreated(tab: chrome.tabs.Tab) {
    if (tab.id !== undefined && tab.id !== chrome.tabs.TAB_ID_NONE) {
        global.tabs[tab.id] = new Tab(tab.id);
    }
}

function handleRemoved(tabId: number, removeInfo: chrome.tabs.TabRemoveInfo) {
    delete global.tabs[tabId];
}

function handleReplaced(addedTabId: number, removedTabId: number) {
    delete global.tabs[removedTabId];
    global.tabs[addedTabId] = new Tab(addedTabId);
}

export default {
    handleActivated,
    handleCreated,
    handleRemoved,
    handleReplaced,
};
