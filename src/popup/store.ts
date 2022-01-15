import { createStore } from 'redux';

interface UpdateStateAction {
    type: 'UPDATE_STATE';
    value: {[key: string]: number};
}

interface ClearTokensAction {
    type: 'CLEAR_TOKENS';
}

type Action = UpdateStateAction | ClearTokensAction;

const reducer = (state: any | undefined, action: Action) => {
    state = (state instanceof Object) ? state : {};

    switch (action.type) {
        case 'UPDATE_STATE':
            return {
                ...state,
                ...action.value,
            };
        case 'CLEAR_TOKENS':
            chrome.runtime.sendMessage({ clear: true });
            return {};
        default:
            return state;
    }
};

export const store = createStore(reducer, {});
