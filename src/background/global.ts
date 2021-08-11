import Tab from '@background/tab';

const tabs: { [index: number]: Tab } = {}
let activeTabId: number = chrome.tabs.TAB_ID_NONE;

// Loads all the existings tabs.
chrome.tabs.query({}, function (existingTabs: chrome.tabs.Tab[]) {
    existingTabs.forEach(tab => {
        if (tab.id !== undefined) {
            tabs[tab.id] = new Tab(tab.id);
        }
    });
});

// Finds which tab is currently active.
chrome.tabs.query({ active: true, currentWindow: true }, function (tabs: chrome.tabs.Tab[]) {
    const [tab] = tabs;
    if (tab.id !== undefined) {
        activeTabId = tab.id;
    }
});

export default {
    activeTabId,
    tabs,
};
