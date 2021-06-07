import Tab from '@background/tab';

const tabs: { [index: number]: Tab } = {}

// Loads all the existings tabs.
chrome.tabs.query({}, function (existingTabs: chrome.tabs.Tab[]) {
    existingTabs.forEach(tab => {
        if (tab.id !== undefined) {
            tabs[tab.id] = new Tab(tab.id);
        }
    });
});

export default { tabs };
