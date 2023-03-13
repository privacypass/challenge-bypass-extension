import { BasicPublicTokenType, RateLimitedTokenType, fetchPublicVerifToken } from './pubVerifToken';

import { parseWWWAuthHeader } from './httpAuthScheme';
import { uint8ToB64URL } from './util';

const PRIVACY_PASS_EXTENSION_ID = 1423;

chrome.runtime.onInstalled.addListener((details) => {
    console.log('start the installation', details);
    chrome.declarativeNetRequest
        .updateSessionRules({ removeRuleIds: [PRIVACY_PASS_EXTENSION_ID] })
        .catch((e: unknown) => console.log(`failed to remove session rules:`, e));

    // chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
    //     console.log(`paso por debug:
    //     rulesetId:      ${info.rule.rulesetId},
    //     ruleId:         ${info.rule.ruleId},
    //     frameId:        ${info.request.frameId},
    //     initiator:      ${info.request.initiator},
    //     method:         ${info.request.method},
    //     partentFrameId: ${info.request.partentFrameId},
    //     requestId:      ${info.request.requestId},
    //     tabId:          ${info.request.tabId},
    //     type:           ${info.request.type},
    //     url:            ${info.request.url},
    //     `);
    // });
});

// chrome.declarativeNetRequest.getDynamicRules().then((r) => console.log('rules dyn:', r));
// chrome.declarativeNetRequest.getSessionRules().then((r) => console.log('rules ses:', r));

async function header_to_token(requestId: string, header: string): Promise<string | null> {
    const tokenDetails = parseWWWAuthHeader(header);
    if (tokenDetails.length === 0) {
        return null;
    }

    console.log('new token details for: ', requestId);
    const td = tokenDetails[0];
    switch (td.type) {
        case BasicPublicTokenType:
            console.log(`type of challenge: ${td.type} is supported`);
            const token = await fetchPublicVerifToken(td);
            const encodedToken = uint8ToB64URL(token.serialize());
            console.log('creo token for: ', requestId, encodedToken);
            return encodedToken;

        case RateLimitedTokenType:
            console.log(`type of challenge: ${td.type} is not supported yet.`);
            break;
        default:
            console.log(`unrecognized type of challenge: ${td.type}`);
    }
    return null;
}

interface LocalCachedData {
    reqId: string;
    url: string;
    hdr: string;
}

chrome.webRequest.onSendHeaders.addListener(
    (details) => {
        void (async () => {
            console.log('onSendHdr', details.requestId);
            console.log('onSendHdr', details.url);
            console.log('onSendHdr', details.requestHeaders);

            const key = details.url;
            const x: Record<string, LocalCachedData | undefined> = await chrome.storage.local.get([
                key,
            ]);
            if (!x) {
                return;
            }
            const { [key]: w } = x;
            if (!w) {
                return;
            }
            console.log(`onSendHdr (get) reqId: ${details.requestId} value:`, w);
            if (w.url !== details.url) {
                return;
            }

            chrome.storage.local
                .remove([key])
                .catch((e: unknown) => console.log('error removing key', e));

            if (!details.requestHeaders) {
                return;
            }
            const hdr = details.requestHeaders.find(
                (x) => x.name.toLowerCase() === 'authorization',
            );
            if (hdr) {
                console.log('the request has a token:', hdr.value);
                // Since the request has a token, we don't need the
                // rule that adds Authorization header.
                chrome.declarativeNetRequest
                    .updateSessionRules({
                        removeRuleIds: [PRIVACY_PASS_EXTENSION_ID],
                    })
                    .catch((e: unknown) => console.log(`failed to remove session rules:`, e));
            }
        })();
    },
    { urls: ['<all_urls>'] },
    ['requestHeaders'],
);

chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
        console.log('onHdrRcv', details.requestId);
        if (!details.responseHeaders) {
            return;
        }
        const hdr = details.responseHeaders.find((x) => x.name.toLowerCase() == 'www-authenticate');
        if (!hdr) {
            return;
        }

        console.log('onHdrRcv', details.requestId);
        console.log('onHdrRcv', details.url);
        console.log('onHdrRcv', details.responseHeaders);

        if (!hdr.value) {
            return;
        }
        const key = details.url;
        const value: LocalCachedData = {
            reqId: details.requestId,
            url: details.url,
            hdr: hdr.value,
        };

        // we need to signal that one token was created for this URL
        chrome.storage.local.set({ [key]: value }).catch((e: unknown) => {
            console.log(`failed to access storage:`, e);
        });

        console.log(`onHdrRcv (set) reqId: ${details.requestId} key: ${key} value:`, value);
        (async (privateTokenChl) => {
            const w3HeaderValue = await header_to_token(details.requestId, privateTokenChl);
            if (w3HeaderValue === null) {
                return;
            }

            console.log('onBfeSendHdr privateTokenChl:', privateTokenChl);
            console.log('onBfeSendHdr w3HeaderValue:', w3HeaderValue);

            // Add a rule to declarativeNetRequest here if you want to block
            // or modify a header from this request. The rule is registered and
            // changes are observed between the onBeforeSendHeaders and
            // onSendHeaders methods.
            chrome.declarativeNetRequest.updateSessionRules(
                {
                    removeRuleIds: [PRIVACY_PASS_EXTENSION_ID],
                    addRules: [
                        {
                            id: PRIVACY_PASS_EXTENSION_ID,
                            priority: 1,
                            action: {
                                type: chrome.declarativeNetRequest.RuleActionType.MODIFY_HEADERS,
                                requestHeaders: [
                                    {
                                        header: 'Authorization',
                                        operation: chrome.declarativeNetRequest.HeaderOperation.SET,
                                        value: 'PrivateToken token=' + w3HeaderValue,
                                    },
                                ],
                            },
                            condition: {
                                // Note: The urlFilter must be composed of only ASCII characters.
                                urlFilter: new URL(details.url).toString(),
                                resourceTypes: [
                                    chrome.declarativeNetRequest.ResourceType.MAIN_FRAME,
                                ],
                            },
                        },
                    ],
                },
                async () => {
                    console.log('The rule onHdrRcv was succesfully applied');
                    const [tab] = await chrome.tabs.query({
                        active: true,
                        lastFocusedWindow: true,
                    });
                    if (!tab.id || tab.id === chrome.tabs.TAB_ID_NONE) {
                        throw new Error('no tabId was found for redirection.');
                    }
                    await chrome.tabs.update(tab.id, { url: details.url });
                },
            );
        })(hdr.value).catch((e: unknown) => {
            console.log(`onHdrRcv an error:`, e);
        });
    },
    { urls: ['<all_urls>'] },
    ['responseHeaders'],
);
