import { forceUpdateIcon } from '..'
import { Providers, Provider } from '../providers';
import { LocalStorage, generatePrefixFromID, clearAllPasses }  from '../storage'

export function handleReceivedMessage(request: any, _sender: chrome.runtime.MessageSender, sendResponse: Function): void {

    // -------------------------------------------------------------------------
    if (request.clear === true) {
        clearAllPasses();

        // Update the browser action icon after clearing the tokens.
        forceUpdateIcon();

        return;
    }

    // -------------------------------------------------------------------------
    if (request.tokensCount === true) {
        const response: {[key: string]: number} = {};

        for (const provider of Providers) {
            if ((typeof request.providerID !== 'number') || (request.providerID === provider.ID)) {
                const storage = new LocalStorage(
                    generatePrefixFromID(provider.ID)
                );

                const tokensJSON: string | null = storage.getItem(Provider.TOKEN_STORE_KEY);
                if (tokensJSON === null) continue;

                try {
                    const tokensArray: string[] = JSON.parse(tokensJSON);

                    response[ provider.ID.toString() ] = Number(tokensArray.length);
                }
                catch (error: any) {}
            }
        }

        sendResponse(response);
        return;
    }

    // -------------------------------------------------------------------------
}
