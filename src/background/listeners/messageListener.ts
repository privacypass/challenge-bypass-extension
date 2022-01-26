import { forceUpdateIcon } from '..'
import { Providers, Provider } from '../providers';
import { LocalStorage, generatePrefixFromID, clearAllPasses }  from '../storage'

function getAllPasses(providerID: number | void): {[key: string]: string[]} {
    const response: {[key: string]: string[]} = {};

    for (const provider of Providers) {
        if ((providerID === undefined) || (providerID === provider.ID)) {
            try {
                const storage = new LocalStorage(
                    generatePrefixFromID(provider.ID)
                );

                const tokensJSON: string | null = storage.getItem(Provider.TOKEN_STORE_KEY);

                const tokensArray: string[] = (tokensJSON === null) ? [] : JSON.parse(tokensJSON);

                response[ provider.ID.toString() ] = tokensArray;
            }
            catch (error: any) {}
        }
    }

    return response;
}

function addPasses(providerID: string, newTokensArray: string[]): boolean {
    try {
        const provider: (typeof Provider) | void = Providers.find(p => p.ID.toString() === providerID);
        if (provider === undefined) throw 'no matching provider for ID value';

        const storage = new LocalStorage(
            generatePrefixFromID(provider.ID)
        );

        const tokensJSON: string | null = storage.getItem(Provider.TOKEN_STORE_KEY);

        const oldTokensArray: string[] = (tokensJSON === null) ? [] : JSON.parse(tokensJSON);

        const mergedTokensArray: string[] = [
            ...oldTokensArray,
            ...(newTokensArray.filter(token => oldTokensArray.indexOf(token) === -1))
        ];

        storage.setItem(
            Provider.TOKEN_STORE_KEY,
            JSON.stringify(mergedTokensArray),
        );

        return true;
    }
    catch (error: any) {
        return false;
    }
}

export function handleReceivedMessage(request: any, _sender: chrome.runtime.MessageSender, sendResponse: Function): void {

    // -------------------------------------------------------------------------
    if (request.tokensCount === true) {
        const allPasses: {[key: string]: string[]} = getAllPasses(request.providerID);
        const response:  {[key: string]: number  } = {};

        for (const providerID in allPasses) {
            response[providerID] = Number(allPasses[providerID].length);
        }

        sendResponse(response);
        return;
    }

    // -------------------------------------------------------------------------
    if (request.backup === true) {
        const allPasses: {[key: string]: string[]} = getAllPasses(request.providerID);

        sendResponse(allPasses);
        return;
    }

    // -------------------------------------------------------------------------
    if (request.restore === true) {
        const backup: {[key: string]: string[]} | void = request.backup;
        let did_restore: boolean = false;

        if (backup !== undefined) {
            for (const providerID in backup) {
                if (addPasses(providerID, backup[providerID]) && !did_restore) {
                    did_restore = true;
                }
            }
        }

        if (did_restore) {
            // Update the browser action icon after restoring tokens.
            forceUpdateIcon();
        }

        sendResponse(did_restore);
        return;
    }

    // -------------------------------------------------------------------------
    if (request.clear === true) {
        clearAllPasses();

        // Update the browser action icon after clearing the tokens.
        forceUpdateIcon();

        return;
    }

    // -------------------------------------------------------------------------
}
