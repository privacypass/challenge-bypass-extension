import { createStore } from 'redux';

interface ObtainStateAction {
    type: 'OBTAIN_STATE';
}

interface UpdateStateAction {
    type: 'UPDATE_STATE';
    value: {[key: string]: number};
}

interface BackupTokensAction {
    type: 'BACKUP_TOKENS';
}

interface RestoreTokensAction {
    type: 'RESTORE_TOKENS';
}

interface ClearTokensAction {
    type: 'CLEAR_TOKENS';
}

type Action = ObtainStateAction | UpdateStateAction | BackupTokensAction | RestoreTokensAction | ClearTokensAction;

const reducer = (state: any | undefined, action: Action) => {
    state = (state instanceof Object) ? state : {};

    switch (action.type) {
        case 'OBTAIN_STATE':
            chrome.runtime.sendMessage({ tokensCount: true }, (response: any) => {
                if ((response !== undefined) && (response !== null) && (response instanceof Object)) {
                    store.dispatch({
                        type:  'UPDATE_STATE',
                        value: response
                    });
                }
            });
            return state;
        case 'UPDATE_STATE':
            return {
                ...state,
                ...action.value,
            };
        case 'BACKUP_TOKENS':
            chrome.runtime.sendMessage({ backup: true }, (response: any) => {
                if ((response !== undefined) && (response !== null) && (response instanceof Object)) {
                    try {
                        // open save-as dialog

                        let url: string;
                        if (window.Blob === undefined || window.URL === undefined) {
                            url = JSON.stringify(response, null, 2);
                            url = btoa(url);
                            url = `data:application/json;base64,${url}`;
                        }
                        else {
                            const blob = new window.Blob([JSON.stringify(response, null, 2)], {type : 'application/json'});
                            url = window.URL.createObjectURL(blob);
                        }

                        const anchor    = window.document.createElement('a');
                        const timestamp = (new Date()).toISOString().replace(/\.\d+Z$/, '').replace('T', '-T').replace(/[:]/g, '-');
                        const filename  = (`${chrome.i18n.getMessage('appName')}-${chrome.i18n.getMessage('labelFileBackup')}.${timestamp}.json`).replace(/(?:[\/\\\<\>\|\?\*:"]|[\s\r\n])+/g, '');
                        anchor.setAttribute('href', url);
                        anchor.setAttribute('download', filename);
                        anchor.click();
                    }
                    catch(e) {}
                }
            });
            return state;
        case 'RESTORE_TOKENS':
            (async () => {

                const readFile = function (event: Event) {
                    event.stopPropagation();
                    event.stopImmediatePropagation();

                    const input: HTMLInputElement = <HTMLInputElement>event.target;
                    const files: FileList | null  = input.files;
                    if (files === null) return;

                    for (let file_index=0; file_index < files.length; file_index++) {
                        const reader = new FileReader();

                        reader.onload = function(){
                            try {
                                if ((typeof reader.result === 'string') && (reader.result.length > 0)) {
                                    const backupJSON: string = reader.result;
                                    const backup: {[key: string]: string[]} = JSON.parse(backupJSON);

                                    chrome.runtime.sendMessage({ restore: true, backup }, (response: any) => {
                                        if (response === true) {
                                            store.dispatch({ type: 'OBTAIN_STATE' });
                                        }
                                    });
                                }
                            }
                            catch(e) {}
                        };

                        reader.readAsText(
                            files[file_index]
                        );
                    }
                };

                try {
                    const input = window.document.createElement('input');
                    input.setAttribute('type',   'file');
                    input.setAttribute('accept', 'text/plain, application/json, .txt, .json');
                    input.addEventListener('change', readFile);
                    input.click();
                }
                catch(e) {}
            })();

            return state;
        case 'CLEAR_TOKENS':
            chrome.runtime.sendMessage({ clear: true });
            return {};
        default:
            return state;
    }
};

export const store = createStore(reducer, {});
