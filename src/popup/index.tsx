import '@popup/styles/body.scss';

import { App } from '@popup/components/App';
import React from 'react';
import ReactDOM from 'react-dom';
import { Provider } from 'react-redux';
import { store } from './store';

ReactDOM.render(
    <Provider store={store}>
        <App />
    </Provider>,
    document.getElementById('root'),
);

// TODO Using Message passing is dirty. It's better to use chrome.storage for sharing
// common data between the popup and the background script.
chrome.runtime.sendMessage({ key: 'cf-tokens' }, (response) => {
    if (response !== undefined && typeof response === 'string') {
        store.dispatch({
            type: 'UPDATE_STATE',
            key: 'cf-tokens',
            value: response,
        });
    }
});
