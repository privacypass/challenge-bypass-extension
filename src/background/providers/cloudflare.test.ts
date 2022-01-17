import { jest } from '@jest/globals';
import { CloudflareProvider } from './cloudflare';
import Token from '../token';

beforeEach(() => {
  jest.useFakeTimers();
  jest.spyOn(global, 'setTimeout');
});

afterEach(() => {
  jest.clearAllTimers();
  jest.useRealTimers();
});

export class StorageMock {
    store: Map<string, string>;

    constructor() {
        this.store = new Map();
    }

    getItem(key: string): string | null {
        return this.store.get(key) ?? null;
    }

    setItem(key: string, value: string): void {
        this.store.set(key, value);
    }
}

test('getStoredTokens', () => {
    const storage = new StorageMock();
    const updateIcon = jest.fn();
    const navigateUrl = jest.fn();

    const provider = new CloudflareProvider(storage, { updateIcon, navigateUrl });
    const tokens = [new Token(), new Token()];
    provider['setStoredTokens'](tokens);
    const storedTokens = provider['getStoredTokens']();
    expect(storedTokens.map((token) => token.toString())).toEqual(
        tokens.map((token) => token.toString()),
    );
});

test('setStoredTokens', () => {
    const storage = new StorageMock();
    const updateIcon = jest.fn();
    const navigateUrl = jest.fn();

    const provider = new CloudflareProvider(storage, { updateIcon, navigateUrl });
    const tokens = [new Token(), new Token()];
    provider['setStoredTokens'](tokens);
    const storedTokens = JSON.parse(storage.store.get('tokens')!);
    expect(storedTokens).toEqual(tokens.map((token) => token.toString()));
});

test('getBadgeText', () => {
    const storage = new StorageMock();
    const updateIcon = jest.fn();
    const navigateUrl = jest.fn();

    const provider = new CloudflareProvider(storage, { updateIcon, navigateUrl });
    const tokens = [new Token(), new Token()];
    provider['setStoredTokens'](tokens);
    const text = provider['getBadgeText']();
    expect(text).toBe('2');
});

/*
 * The issuance involves handleBeforeRequest listener.
 * 1. Firstly, the listener check if the request looks like the one that we
 * should send an issuance request.
 * 2. If it passes the check, the listener returns the cancel command to
 * cancel the request. If not, it returns nothing and let the request
 * continue.
 * 3. At the same time the listener returns, it calls a private method
 * "issue" to send an issuance request to the server and the method return
 * an array of issued tokens.
 * 4. The listener stored the issued tokens in the storage.
 * 5. The listener reloads the tab to get the proper web page for the tab.);
 */
describe('issuance', () => {
    describe('handleBeforeRequest', () => {
        test('valid request', async () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new CloudflareProvider(storage, { updateIcon, navigateUrl });
            const tokens = [new Token(), new Token(), new Token()];
            const issue = jest.fn(async () => {
                return tokens;
            });
            provider['issue'] = issue;
            const url = 'https://captcha.website/?__cf_chl_captcha_tk__=query-param';
            const details = {
                method: 'POST',
                url,
                requestId: 'xxx',
                frameId: 1,
                parentFrameId: 1,
                tabId: 1,
                type: 'xmlhttprequest' as chrome.webRequest.ResourceType,
                timeStamp: 1,
                requestBody: {
                    formData: {
                        'h-captcha-response': ['body-param'],
                    },
                },
            };
            const result = provider.handleBeforeRequest(details);
            expect(result).toEqual({ cancel: true });

            expect(setTimeout).toHaveBeenCalledTimes(1);
            expect(setTimeout).toHaveBeenLastCalledWith(expect.any(Function), 0);

            jest.runAllTimers();
            await Promise.resolve();

            expect(issue.mock.calls.length).toBe(1);
            expect(issue).toHaveBeenCalledWith(url, {
                'h-captcha-response': 'body-param',
            });

            // Expect the tokens are added.
            const storedTokens = provider['getStoredTokens']();
            expect(storedTokens.map((token) => token.toString())).toEqual(
                tokens.map((token) => token.toString()),
            );

            expect(updateIcon.mock.calls.length).toBe(1);
            expect(updateIcon).toHaveBeenCalledWith(tokens.length.toString());

            expect(navigateUrl.mock.calls.length).toBe(1);
            expect(navigateUrl).toHaveBeenCalledWith('https://captcha.website/');
        });

        /*
         * The request is invalid if any of the followings is true:
         * 1. It has no url param of any of the followings:
         *    a. '__cf_chl_captcha_tk__'
         *    b. '__cf_chl_managed_tk__'
         * 2. It has no body param of any of the followings:
         *    a. 'g-recaptcha-response'
         *    b. 'h-captcha-response'
         *    c. 'cf_captcha_kind'
         */
        test('invalid request', async () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new CloudflareProvider(storage, { updateIcon, navigateUrl });
            const issue = jest.fn(async () => []);
            provider['issue'] = issue;
            const details = {
                method: 'GET',
                url: 'https://cloudflare.com/',
                requestId: 'xxx',
                frameId: 1,
                parentFrameId: 1,
                tabId: 1,
                type: 'xmlhttprequest' as chrome.webRequest.ResourceType,
                timeStamp: 1,
                requestBody: {},
            };
            const result = provider.handleBeforeRequest(details);
            expect(result).toBeUndefined();

            expect(setTimeout).not.toHaveBeenCalled();
            expect(issue).not.toHaveBeenCalled();
            expect(updateIcon).not.toHaveBeenCalled();
            expect(navigateUrl).not.toHaveBeenCalled();
        });
    });
});

/*
 * The redemption involves handleHeadersReceived and handleBeforeSendHeaders
 * listeners. In handleHeadersReceived listener,
 * 1. Firstly, the listener check if the response is the challenge page and
 * it supports Privacy Pass redemption.
 * 2. If it passes the check, the listener gets a token from the storage to
 * redeem.
 * 3. The listener sets "redeemInfo" property which includes the request id
 * and the mentioned token. The property will be used by
 * handleBeforeSendHeaders to redeem the token.
 * 4. The listener returns the redirect command so that the browser will
 * send the same request again with the token attached.
 *
 * In handleBeforeSendHeaders,
 * 1. The listener will check if the provided request id matches the
 * request id in "redeemInfo". If so, it means that the request is from the
 * redirect command returned by handleHeadersReceived. If not, it returns
 * nothing and let the request continue.
 * 2. If it passes the check, the listener attaches the token from
 * "redeemInfo" in the "challenge-bypass-token" HTTP header and clears the
 * "redeemInfo" property because "redeemInfo" is used already.
 */
describe('redemption', () => {
    describe('handleHeadersReceived', () => {
        const validDetails = {
            url: 'https://cloudflare.com/',
            requestId: 'xxx',
            frameId: 1,
            parentFrameId: 1,
            tabId: 1,
            type: 'main_frame' as chrome.webRequest.ResourceType,
            timeStamp: 1,

            statusLine: 'HTTP/1.1 403 Forbidden',
            statusCode: 403,
            responseHeaders: [
                {
                    name: 'cf-chl-bypass',
                    value: '1',
                },
            ],
            method: 'GET',
        };

        test('valid response with tokens', () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new CloudflareProvider(storage, { updateIcon, navigateUrl });
            const tokens = [new Token(), new Token(), new Token()];
            provider['setStoredTokens'](tokens);
            const details = validDetails;
            const result = provider.handleHeadersReceived(details);
            expect(result).toEqual({ redirectUrl: details.url });
            // Expect redeemInfo to be set.
            const redeemInfo = provider['redeemInfo'];
            expect(redeemInfo!.requestId).toEqual(details.requestId);
            expect(redeemInfo!.token.toString()).toEqual(tokens[0].toString());
            // Expect a token is used.
            const storedTokens = provider['getStoredTokens']();
            expect(storedTokens.map((token) => token.toString())).toEqual(
                tokens.slice(1).map((token) => token.toString()),
            );
        });

        test('valid response without tokens', () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new CloudflareProvider(storage, { updateIcon, navigateUrl });
            provider['setStoredTokens']([]);
            const details = validDetails;
            const result = provider.handleHeadersReceived(details);
            expect(result).toBeUndefined();
        });

        test('captcha.website response', () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new CloudflareProvider(storage, { updateIcon, navigateUrl });
            const tokens = [new Token(), new Token(), new Token()];
            provider['setStoredTokens'](tokens);
            const details = validDetails;
            details.url = 'https://captcha.website/';
            const result = provider.handleHeadersReceived(details);
            expect(result).toBeUndefined();
        });

        /*
         * The response is invalid if any of the followings is true:
         * 1. The status code is not 403.
         * 2. There is no HTTP header of "cf-chl-bypass: 1"
         */
        test('invalid response', () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new CloudflareProvider(storage, { updateIcon, navigateUrl });
            const tokens = [new Token(), new Token(), new Token()];
            provider['setStoredTokens'](tokens);
            const details = {
                url: 'https://cloudflare.com/',
                requestId: 'xxx',
                frameId: 1,
                parentFrameId: 1,
                tabId: 1,
                type: 'main_frame' as chrome.webRequest.ResourceType,
                timeStamp: 1,

                statusLine: 'HTTP/1.1 403 Forbidden',
                statusCode: 403,
                method: 'GET',
            };
            const result = provider.handleHeadersReceived(details);
            expect(result).toBeUndefined();
        });
    });

    describe('handleBeforeSendHeaders', () => {
        test('with redeemInfo', () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new CloudflareProvider(storage, { updateIcon, navigateUrl });

            const token = Token.fromString(
                '{"input":[238,205,51,250,226,251,144,68,170,68,235,25,231,152,125,63,215,10,42,37,65,157,56,22,98,23,129,9,157,179,223,64],"factor":"0x359953995df006ba98bdcf1383a4c75ca79ae41d4e718dcb051832ce65c002bc","blindedPoint":"BCrzbuVf2eSD/5NtR+o09ovo+oRWAwjwopzl7lb+IuOPuj/ctLkdlkeJQUeyjtUbfgJqU4BFNBRz9ln4z3Dk7Us=","unblindedPoint":"BLKf1op+oq4FcbNdP5vygTkGO3WWLHD6oXCCZDfaFyuFlruih49BStHm6QxtZZAqgCR9i6SsO6VP69hHnfBDNeg=","signed":{"blindedPoint":"BKEnbsQSwnHCxEv4ppp6XuqLV60FiQpF8YWvodQHdnmFHv7CKyWHqBLBW8fJ2uuV+uLxl99+VRYPxr8Q8E7i2Iw=","unblindedPoint":"BA8G3dHM554FzDiOtEsSBu0XYW8p5vA2OIEvnYQcJlRGHTiq2N6j3BKUbiI7I6fAy2vsOrwhrLGHOD+q7YxO+UM="}}',
            );
            const redeemInfo = {
                requestId: 'xxx',
                token,
            };
            provider['redeemInfo'] = redeemInfo;
            const details = {
                method: 'GET',
                url: 'https://cloudflare.com/',
                requestId: 'xxx',
                frameId: 1,
                parentFrameId: 1,
                tabId: 1,
                type: 'main_frame' as chrome.webRequest.ResourceType,
                timeStamp: 1,
                requestHeaders: [],
            };
            const result = provider.handleBeforeSendHeaders(details);
            expect(result).toEqual({
                requestHeaders: [
                    {
                        name: 'challenge-bypass-token',
                        value: 'eyJ0eXBlIjoiUmVkZWVtIiwiY29udGVudHMiOlsiN3Mweit1TDdrRVNxUk9zWjU1aDlQOWNLS2lWQm5UZ1dZaGVCQ1oyejMwQT0iLCJyeXRSRExLN3J2THVhd09XZkJ0RXJTclVuUWpIaGpLbkNKK3RqQnhQSFYwPSIsImV5SmpkWEoyWlNJNkluQXlOVFlpTENKb1lYTm9Jam9pYzJoaE1qVTJJaXdpYldWMGFHOWtJam9pYVc1amNtVnRaVzUwSW4wPSJdfQ==',
                    },
                ],
            });
            const newRedeemInfo = provider['redeemInfo'];
            expect(newRedeemInfo).toBeNull();
            expect(updateIcon).not.toHaveBeenCalled();
        });

        test('without redeemInfo', () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new CloudflareProvider(storage, { updateIcon, navigateUrl });

            const details = {
                method: 'GET',
                url: 'https://cloudflare.com/',
                requestId: 'xxx',
                frameId: 1,
                parentFrameId: 1,
                tabId: 1,
                type: 'main_frame' as chrome.webRequest.ResourceType,
                timeStamp: 1,
                requestHeaders: [],
            };
            const result = provider.handleBeforeSendHeaders(details);
            expect(result).toBeUndefined();
            expect(updateIcon).not.toHaveBeenCalled();
        });
    });
});
