import { createStore } from 'redux';

interface UpdateStateAction {
    type: 'UPDATE_STATE';
    key: string;
    value: string;
}

interface ClearTokensAction {
    type: 'CLEAR_TOKENS';
}

type Action = UpdateStateAction | ClearTokensAction;

const reducer = (state: object | undefined, action: Action) => {
    switch (action.type) {
        case 'UPDATE_STATE':
            return {
                ...state,
                [action.key]: JSON.parse(action.value),
            };
        case 'CLEAR_TOKENS':
            // TODO Using Message passing is dirty. It's better to use chrome.storage for sharing
            // common data between the popup and the background script.
            chrome.runtime.sendMessage({ clear: true });
            return {};
    }
};

export const store = createStore(reducer, {});
