import global from '@background/global';
import Tab    from '@background/tab';

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
    handleCreated,
    handleRemoved,
    handleReplaced,
};
