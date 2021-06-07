import tabs       from '@background/listeners/tabs';

chrome.tabs.onCreated.addListener(
    tabs.handleCreated,
);

chrome.tabs.onReplaced.addListener(
    tabs.handleReplaced,
);

chrome.tabs.onRemoved.addListener(
    tabs.handleRemoved,
);
