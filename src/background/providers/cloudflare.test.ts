import { jest } from '@jest/globals';
import { CloudflareProvider } from './cloudflare';
import Token from '../token';

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

test('setStoredTokens', () => {
    const storage = new StorageMock();
    const updateIcon = jest.fn();
    const navigateUrl = jest.fn();

    const provider = new CloudflareProvider(storage, { updateIcon, navigateUrl });
    const tokens = [new Token(), new Token()];
    provider['setStoredTokens'](tokens);

    expect(updateIcon.mock.calls.length).toBe(1);
    expect(updateIcon).toHaveBeenCalledWith(tokens.length.toString());

    const storedTokens = JSON.parse(storage.store.get('tokens')!);
    expect(storedTokens).toEqual(tokens.map((token) => token.toString()));

    expect(updateIcon.mock.calls.length).toBe(1);
    expect(navigateUrl).not.toHaveBeenCalled();
});

test('getStoredTokens', () => {
    const storage = new StorageMock();
    const updateIcon = jest.fn();
    const navigateUrl = jest.fn();

    const provider = new CloudflareProvider(storage, { updateIcon, navigateUrl });
    const tokens = [new Token(), new Token()];
    provider['setStoredTokens'](tokens);

    expect(updateIcon.mock.calls.length).toBe(1);
    expect(updateIcon).toHaveBeenCalledWith(tokens.length.toString());

    const storedTokens = provider['getStoredTokens']();
    expect(storedTokens.map((token) => token.toString())).toEqual(
        tokens.map((token) => token.toString()),
    );

    expect(updateIcon.mock.calls.length).toBe(1);
    expect(navigateUrl).not.toHaveBeenCalled();
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
 * The issuance involves handleBeforeRequest and handleBeforeSendHeaders listeners.
 *
 * In handleBeforeRequest listener,
 * 1. Check that the request matches the criteria for issuing new tokens.
 *    Such requests are submitting a solved captcha to the provider
 *    on a website controlled by the provider.
 * 2. If so, the listener sets the "issueInfo" property,
 *    which includes the request id for subsequent processing.
 *
 * In handleBeforeSendHeaders,
 * 1. Check that the "issueInfo" property is set, and its request id is a match.
 * 2. If so, complete the check to determine that the request matches the criteria for issuing new tokens.
 * 3. If so,
 * 3a. Cancel the original request.
 * 3b. Initiate a secondary request to the provider for the issuing of signed tokens.
 */
describe('issuance', () => {
    describe('handleBeforeRequest', () => {

        beforeEach(() => {
            jest.useFakeTimers();
            jest.spyOn(global, 'setTimeout');
        });

        afterEach(() => {
            jest.clearAllTimers();
            jest.useRealTimers();
        });

        const validDetails: chrome.webRequest.WebRequestBodyDetails = {
            method: 'POST',
            url: 'https://captcha.website/?__cf_chl_captcha_tk__=query-param',
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
            let result, issueInfo;

            const bodyDetails: chrome.webRequest.WebRequestBodyDetails = validDetails;
            result = provider.handleBeforeRequest(bodyDetails);
            expect(result).toEqual({ cancel: false });

            // Expect issueInfo to be set.
            issueInfo = provider['issueInfo'];
            expect(issueInfo!.requestId).toEqual(bodyDetails.requestId);
            expect(issueInfo!.url).toEqual(bodyDetails.url);
            expect(issueInfo!.formData).toEqual(bodyDetails.requestBody!.formData);

            const headDetails: any = {
                ...validDetails,
                requestHeaders: []
            };
            delete headDetails.requestBody;

            result = provider.handleBeforeSendHeaders(<chrome.webRequest.WebRequestHeadersDetails>headDetails);
            expect(result).toEqual({ cancel: true });

            // Expect issueInfo to be unset.
            issueInfo = provider['issueInfo'];
            expect(issueInfo).toBeNull();

            expect(setTimeout).toHaveBeenCalledTimes(1);
            expect(setTimeout).toHaveBeenLastCalledWith(expect.any(Function), 0);
            jest.runAllTimers();
            await Promise.resolve();

            expect(issue.mock.calls.length).toBe(1);
            expect(issue).toHaveBeenCalledWith(headDetails.url, {
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

        test('[workaround] invalid request: with a valid referer header', async () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new CloudflareProvider(storage, { updateIcon, navigateUrl });
            const tokens = [new Token(), new Token(), new Token()];
            const issue = jest.fn(async () => {
                return tokens;
            });
            provider['issue'] = issue;
            let result, issueInfo;

            const bodyDetails: chrome.webRequest.WebRequestBodyDetails = {
                ...validDetails,
                url: validDetails.url.substring(0, validDetails.url.indexOf('?')),
            };
            result = provider.handleBeforeRequest(bodyDetails);
            expect(result).toEqual({ cancel: false });

            // Expect issueInfo to be set.
            issueInfo = provider['issueInfo'];
            expect(issueInfo!.requestId).toEqual(bodyDetails.requestId);
            expect(issueInfo!.url).toEqual(bodyDetails.url);
            expect(issueInfo!.formData).toEqual(bodyDetails.requestBody!.formData);

            const headDetails: any = {
                ...validDetails,
                requestHeaders: [
                    { name: "referer", value: validDetails.url.replace('__cf_chl_captcha_tk__', '__cf_chl_tk') },
                ],
            };
            delete headDetails.requestBody;

            result = provider.handleBeforeSendHeaders(<chrome.webRequest.WebRequestHeadersDetails>headDetails);
            expect(result).toEqual({ cancel: true });

            // Expect issueInfo to be unset.
            issueInfo = provider['issueInfo'];
            expect(issueInfo).toBeNull();

            expect(setTimeout).toHaveBeenCalledTimes(1);
            expect(setTimeout).toHaveBeenLastCalledWith(expect.any(Function), 0);
            jest.runAllTimers();
            await Promise.resolve();

            expect(issue.mock.calls.length).toBe(1);
            expect(issue).toHaveBeenCalledWith(headDetails.url, {
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

        test('invalid request: no query param', () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new CloudflareProvider(storage, { updateIcon, navigateUrl });
            const issue = jest.fn(async () => []);
            provider['issue'] = issue;
            let result, issueInfo;

            const bodyDetails: chrome.webRequest.WebRequestBodyDetails = {
                ...validDetails,
                url: validDetails.url.substring(0, validDetails.url.indexOf('?')),
            };
            result = provider.handleBeforeRequest(bodyDetails);
            expect(result).toEqual({ cancel: false });

            // Expect issueInfo to be set.
            issueInfo = provider['issueInfo'];
            expect(issueInfo!.requestId).toEqual(bodyDetails.requestId);
            expect(issueInfo!.url).toEqual(bodyDetails.url);
            expect(issueInfo!.formData).toEqual(bodyDetails.requestBody!.formData);

            const headDetails: any = {
                ...validDetails,
                requestHeaders: []
            };
            delete headDetails.requestBody;

            result = provider.handleBeforeSendHeaders(<chrome.webRequest.WebRequestHeadersDetails>headDetails);
            expect(result).toBeUndefined();

            // Expect issueInfo to be unset.
            issueInfo = provider['issueInfo'];
            expect(issueInfo).toBeNull();

            expect(setTimeout).not.toHaveBeenCalled();
            expect(issue).not.toHaveBeenCalled();
            expect(updateIcon).not.toHaveBeenCalled();
            expect(navigateUrl).not.toHaveBeenCalled();
        });

        test('invalid request: no body param', () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new CloudflareProvider(storage, { updateIcon, navigateUrl });
            const issue = jest.fn(async () => []);
            provider['issue'] = issue;
            let result, issueInfo;

            const bodyDetails: chrome.webRequest.WebRequestBodyDetails = {
                ...validDetails,
                requestBody: {},
            };
            result = provider.handleBeforeRequest(bodyDetails);
            expect(result).toBeUndefined();

            // Expect issueInfo to be unset.
            issueInfo = provider['issueInfo'];
            expect(issueInfo).toBeNull();

            const headDetails: any = {
                ...validDetails,
                requestHeaders: []
            };
            delete headDetails.requestBody;

            result = provider.handleBeforeSendHeaders(<chrome.webRequest.WebRequestHeadersDetails>headDetails);
            expect(result).toBeUndefined();

            // Expect issueInfo to be unset.
            issueInfo = provider['issueInfo'];
            expect(issueInfo).toBeNull();

            expect(setTimeout).not.toHaveBeenCalled();
            expect(issue).not.toHaveBeenCalled();
            expect(updateIcon).not.toHaveBeenCalled();
            expect(navigateUrl).not.toHaveBeenCalled();
        });
    });
});

/*
 * The redemption involves handleHeadersReceived and handleBeforeSendHeaders listeners.
 *
 * In handleHeadersReceived listener,
 * 1. Check that the request matches the criteria for redemption.
 *    Such requests have a status code of 403, and a special header.
 * 2. If so, the listener sets the "redeemInfo" property,
 *    and returns a value that causes the request to be resent.
 *
 * In handleBeforeSendHeaders,
 * 1. Check that the "redeemInfo" property is set, and its request id is a match.
 * 2. If so, add headers to include one token for redemption by provider.
 */
describe('redemption', () => {
    describe('handleHeadersReceived', () => {
        const validDetails: chrome.webRequest.WebResponseHeadersDetails = {
            method: 'GET',
            url: 'https://non-issuing-domain.example.com/',
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
        };

        test('valid response with tokens in wallet', () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new CloudflareProvider(storage, { updateIcon, navigateUrl });
            const tokens = [new Token(), new Token(), new Token()];
            provider['setStoredTokens'](tokens);

            expect(updateIcon.mock.calls.length).toBe(1);
            expect(updateIcon).toHaveBeenCalledWith(tokens.length.toString());

            const details: chrome.webRequest.WebResponseHeadersDetails = validDetails;
            const result = provider.handleHeadersReceived(details);
            expect(result).toEqual({ redirectUrl: details.url });

            // Expect redeemInfo to be set.
            const redeemInfo = provider['redeemInfo'];
            expect(redeemInfo!.requestId).toEqual(details.requestId);
            expect(redeemInfo!.token.toString()).toEqual(tokens[0].toString());

            expect(updateIcon.mock.calls.length).toBe(2);
            expect(updateIcon).toHaveBeenLastCalledWith((tokens.length - 1).toString());

            // Expect a token is used.
            const storedTokens = provider['getStoredTokens']();
            expect(storedTokens.map((token) => token.toString())).toEqual(
                tokens.slice(1).map((token) => token.toString()),
            );

            expect(updateIcon.mock.calls.length).toBe(2);
            expect(navigateUrl).not.toHaveBeenCalled();
        });

        test('valid response without tokens in wallet', () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new CloudflareProvider(storage, { updateIcon, navigateUrl });
            provider['setStoredTokens']([]);

            expect(updateIcon.mock.calls.length).toBe(1);
            expect(updateIcon).toHaveBeenCalledWith('0');

            const details: chrome.webRequest.WebResponseHeadersDetails = validDetails;
            const result = provider.handleHeadersReceived(details);
            expect(result).toBeUndefined();

            expect(updateIcon.mock.calls.length).toBe(2);
            expect(updateIcon).toHaveBeenLastCalledWith('0');
            expect(navigateUrl).not.toHaveBeenCalled();
        });

        /*
         * The response is invalid if any of the followings is true:
         * 1. The URL is hosted by a site that issues tokens.
         * 2. The status code is not 403.
         * 3. There is no HTTP header of "cf-chl-bypass: 1"
         */

        test('invalid response: from issuing domain', () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new CloudflareProvider(storage, { updateIcon, navigateUrl });
            const tokens = [new Token(), new Token(), new Token()];
            provider['setStoredTokens'](tokens);

            expect(updateIcon.mock.calls.length).toBe(1);
            expect(updateIcon).toHaveBeenCalledWith(tokens.length.toString());

            const details: chrome.webRequest.WebResponseHeadersDetails = {
                ...validDetails,
                url: 'https://captcha.website/',
            };
            const result = provider.handleHeadersReceived(details);
            expect(result).toBeUndefined();

            expect(updateIcon.mock.calls.length).toBe(1);
            expect(navigateUrl).not.toHaveBeenCalled();
        });

        test('invalid response: wrong status code', () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new CloudflareProvider(storage, { updateIcon, navigateUrl });
            const tokens = [new Token(), new Token(), new Token()];
            provider['setStoredTokens'](tokens);

            expect(updateIcon.mock.calls.length).toBe(1);
            expect(updateIcon).toHaveBeenCalledWith(tokens.length.toString());

            const details: chrome.webRequest.WebResponseHeadersDetails = {
                ...validDetails,
                statusLine: 'HTTP/1.1 200 OK',
                statusCode: 200,
            };
            const result = provider.handleHeadersReceived(details);
            expect(result).toBeUndefined();

            expect(updateIcon.mock.calls.length).toBe(1);
            expect(navigateUrl).not.toHaveBeenCalled();
        });

        test('invalid response: no bypass header', () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new CloudflareProvider(storage, { updateIcon, navigateUrl });
            const tokens = [new Token(), new Token(), new Token()];
            provider['setStoredTokens'](tokens);

            expect(updateIcon.mock.calls.length).toBe(1);
            expect(updateIcon).toHaveBeenCalledWith(tokens.length.toString());

            const details: chrome.webRequest.WebResponseHeadersDetails = {
                ...validDetails,
                responseHeaders: [],
            };
            const result = provider.handleHeadersReceived(details);
            expect(result).toBeUndefined();

            expect(updateIcon.mock.calls.length).toBe(1);
            expect(navigateUrl).not.toHaveBeenCalled();
        });
    });

    describe('handleBeforeSendHeaders', () => {
        const validDetails: chrome.webRequest.WebRequestHeadersDetails = {
            method: 'GET',
            url: 'https://non-issuing-domain.example.com/',
            requestId: 'xxx',
            frameId: 1,
            parentFrameId: 1,
            tabId: 1,
            type: 'main_frame' as chrome.webRequest.ResourceType,
            timeStamp: 1,
            requestHeaders: [],
        };

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

            const details: chrome.webRequest.WebRequestHeadersDetails = validDetails;
            const result = provider.handleBeforeSendHeaders(details);
            expect(result).toEqual({
                requestHeaders: [
                    {
                        name: 'challenge-bypass-token',
                        value: 'eyJ0eXBlIjoiUmVkZWVtIiwiY29udGVudHMiOlsiN3Mweit1TDdrRVNxUk9zWjU1aDlQOWNLS2lWQm5UZ1dZaGVCQ1oyejMwQT0iLCJIWVA2QnlqYmFCK0trNG9qM2Rtazc4Qy9aWWFMVlNYTHZtT0JIMms0QTFRPSIsImV5SmpkWEoyWlNJNkluQXlOVFlpTENKb1lYTm9Jam9pYzJoaE1qVTJJaXdpYldWMGFHOWtJam9pYVc1amNtVnRaVzUwSW4wPSJdfQ==',
                    },
                ],
            });

            const newRedeemInfo = provider['redeemInfo'];
            expect(newRedeemInfo).toBeNull();

            expect(updateIcon).not.toHaveBeenCalled();
            expect(navigateUrl).not.toHaveBeenCalled();
        });

        test('without redeemInfo', () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new CloudflareProvider(storage, { updateIcon, navigateUrl });

            const details: chrome.webRequest.WebRequestHeadersDetails = validDetails;
            const result = provider.handleBeforeSendHeaders(details);
            expect(result).toBeUndefined();

            expect(updateIcon).not.toHaveBeenCalled();
            expect(navigateUrl).not.toHaveBeenCalled();
        });
    });
});
