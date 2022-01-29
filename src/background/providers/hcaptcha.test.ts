import { jest } from '@jest/globals';
import { HcaptchaProvider } from './hcaptcha';
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

    const provider = new HcaptchaProvider(storage, { updateIcon, navigateUrl });
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

    const provider = new HcaptchaProvider(storage, { updateIcon, navigateUrl });
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

    const provider = new HcaptchaProvider(storage, { updateIcon, navigateUrl });
    const tokens = [new Token(), new Token()];
    provider['setStoredTokens'](tokens);
    const text = provider['getBadgeText']();
    expect(text).toBe('2');
});

/*
 * The issuance involves handleBeforeRequest and handleOnCompleted listeners.
 *
 * In handleBeforeRequest listener,
 * 1. Check that the request matches the criteria for issuing new tokens.
 *    Such requests are submitting a solved captcha to the provider
 *    on a website controlled by the provider.
 * 2. If so, the listener sets the "issueInfo" property,
 *    which includes the request id for subsequent processing.
 *
 * In handleOnCompleted,
 * 1. Check that the "issueInfo" property is set, and its request id is a match.
 * 2. If so, initiate a secondary request to the provider for the issuing of signed tokens.
 */
describe('issuance', () => {
    describe('handleBeforeRequest', () => {
        const validDetails: chrome.webRequest.WebRequestBodyDetails = {
            method: 'POST',
            url: 'https://hcaptcha.com/checkcaptcha/xxx?s=00000000-0000-0000-0000-000000000000',
            requestId: 'xxx',
            frameId: 1,
            parentFrameId: 1,
            tabId: 1,
            type: 'xmlhttprequest' as chrome.webRequest.ResourceType,
            timeStamp: 1,
            requestBody: {},
        };

        test('valid request', async () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new HcaptchaProvider(storage, { updateIcon, navigateUrl });
            let result, issueInfo

            const reqDetails: chrome.webRequest.WebRequestBodyDetails = validDetails;
            result = provider.handleBeforeRequest(reqDetails);
            expect(result).toEqual({ cancel: false });

            // Expect issueInfo to be set.
            issueInfo = provider['issueInfo'];
            expect(issueInfo!.requestId).toEqual(reqDetails.requestId);
            expect(issueInfo!.url).toEqual(reqDetails.url);

            const tokens = [new Token(), new Token(), new Token()];
            const issue = jest.fn(async () => {
                return tokens;
            });
            provider['issue'] = issue;

            const resDetails: chrome.webRequest.WebResponseHeadersDetails = {
                ...validDetails,
                statusLine: 'HTTP/1.1 200 OK',
                statusCode: 200,
                responseHeaders: [],
            };
            result = provider.handleOnCompleted(resDetails);
            expect(result).toBeUndefined();
            await Promise.resolve();

            expect(issue.mock.calls.length).toBe(1);
            expect(issue).toHaveBeenCalledWith(issueInfo!.url);

            // Expect the tokens are added.
            const storedTokens = provider['getStoredTokens']();
            expect(storedTokens.map((token) => token.toString())).toEqual(
                tokens.map((token) => token.toString()),
            );

            // Expect issueInfo to be null.
            issueInfo = provider['issueInfo'];
            expect(issueInfo).toBeNull();

            expect(updateIcon.mock.calls.length).toBe(1);
            expect(updateIcon).toHaveBeenCalledWith(tokens.length.toString());

            expect(navigateUrl.mock.calls.length).toBe(1);
            expect(navigateUrl).toHaveBeenCalledWith('https://www.hcaptcha.com/privacy-pass');
        });

        /*
         * The request is invalid if any of the followings is true:
         * 1. It has no url param of any of the followings:
         *    a. 's=00000000-0000-0000-0000-000000000000'
         * 2. Its pathname does not contain of any of the followings:
         *    a. '/checkcaptcha'
         */

        test('invalid request: no query param', () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new HcaptchaProvider(storage, { updateIcon, navigateUrl });

            const details: chrome.webRequest.WebRequestBodyDetails = {
                ...validDetails,
                url: validDetails.url.substring(0, validDetails.url.indexOf('?')),
            };
            const result = provider.handleBeforeRequest(details);
            expect(result).toBeUndefined();

            // Expect issueInfo to be null.
            const issueInfo = provider['issueInfo'];
            expect(issueInfo).toBeNull();

            expect(updateIcon).not.toHaveBeenCalled();
            expect(navigateUrl).not.toHaveBeenCalled();
        });

        test('invalid request: no matching pathname', () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new HcaptchaProvider(storage, { updateIcon, navigateUrl });

            const details: chrome.webRequest.WebRequestBodyDetails = {
                ...validDetails,
                url: validDetails.url.replace(/checkcaptcha/g, 'getcaptcha'),
            };
            const result = provider.handleBeforeRequest(details);
            expect(result).toBeUndefined();

            // Expect issueInfo to be null.
            const issueInfo = provider['issueInfo'];
            expect(issueInfo).toBeNull();

            expect(updateIcon).not.toHaveBeenCalled();
            expect(navigateUrl).not.toHaveBeenCalled();
        });
    });
});

/*
 * The redemption involves handleBeforeRequest and handleBeforeSendHeaders listeners.
 *
 * In handleBeforeRequest listener,
 * 1. Check that the request matches the criteria for redemption.
 *    Such requests are asking for the provider to generate a new captcha.
 * 2. If so, the listener sets the "redeemInfo" property,
 *    which includes the request id for subsequent processing.
 *
 * In handleBeforeSendHeaders,
 * 1. Check that the "redeemInfo" property is set, and its request id is a match.
 * 2. If so, add headers to include one token for redemption by provider.
 */
describe('redemption', () => {
    describe('handleBeforeRequest', () => {
        const validDetails: chrome.webRequest.WebRequestBodyDetails = {
            method: 'POST',
            url: 'https://hcaptcha.com/getcaptcha/xxx?s=11111111-1111-1111-1111-111111111111',
            requestId: 'xxx',
            frameId: 1,
            parentFrameId: 1,
            tabId: 1,
            type: 'xmlhttprequest' as chrome.webRequest.ResourceType,
            timeStamp: 1,
            requestBody: {
                formData: {
                    sitekey:    ['xxx'],
                    motionData: ['xxx'],
                    host:       ['non-issuing-domain.example.com']
                }
            },
        };

        test('valid response with tokens', () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new HcaptchaProvider(storage, { updateIcon, navigateUrl });
            const token = Token.fromString(
                '{"input":[238,205,51,250,226,251,144,68,170,68,235,25,231,152,125,63,215,10,42,37,65,157,56,22,98,23,129,9,157,179,223,64],"factor":"0x359953995df006ba98bdcf1383a4c75ca79ae41d4e718dcb051832ce65c002bc","blindedPoint":"BCrzbuVf2eSD/5NtR+o09ovo+oRWAwjwopzl7lb+IuOPuj/ctLkdlkeJQUeyjtUbfgJqU4BFNBRz9ln4z3Dk7Us=","unblindedPoint":"BLKf1op+oq4FcbNdP5vygTkGO3WWLHD6oXCCZDfaFyuFlruih49BStHm6QxtZZAqgCR9i6SsO6VP69hHnfBDNeg=","signed":{"blindedPoint":"BKEnbsQSwnHCxEv4ppp6XuqLV60FiQpF8YWvodQHdnmFHv7CKyWHqBLBW8fJ2uuV+uLxl99+VRYPxr8Q8E7i2Iw=","unblindedPoint":"BA8G3dHM554FzDiOtEsSBu0XYW8p5vA2OIEvnYQcJlRGHTiq2N6j3BKUbiI7I6fAy2vsOrwhrLGHOD+q7YxO+UM="}}',
            );
            const tokens = [token, new Token(), new Token()];
            let result, redeemInfo;

            provider['setStoredTokens'](tokens);
            expect(updateIcon.mock.calls.length).toBe(1);
            expect(updateIcon).toHaveBeenCalledWith(tokens.length.toString());

            const bodyDetails: chrome.webRequest.WebRequestBodyDetails = validDetails;
            result = provider.handleBeforeRequest(bodyDetails);
            expect(result).toEqual({ cancel: false });

            // Expect redeemInfo to be set.
            redeemInfo = provider['redeemInfo'];
            expect(redeemInfo!.requestId).toEqual(bodyDetails.requestId);

            const headDetails: any = {
                ...validDetails,
                requestHeaders: [],
            };
            delete headDetails.requestBody;

            result = provider.handleBeforeSendHeaders(<chrome.webRequest.WebRequestHeadersDetails>headDetails);
            expect(result).toEqual({
                requestHeaders: [
                    { name: 'challenge-bypass-host',  value: 'hcaptcha.com'     },
                    { name: 'challenge-bypass-path',  value: 'POST /getcaptcha' },
                    { name: 'challenge-bypass-token', value: 'eyJ0eXBlIjoiUmVkZWVtIiwiY29udGVudHMiOlsiN3Mweit1TDdrRVNxUk9zWjU1aDlQOWNLS2lWQm5UZ1dZaGVCQ1oyejMwQT0iLCJhR3ZFRmJaUmN1SnZvcHpSUDBFT1pQb084eDJtdzV6Q3ptUG9mL3AwY3F3PSIsImV5SmpkWEoyWlNJNkluQXlOVFlpTENKb1lYTm9Jam9pYzJoaE1qVTJJaXdpYldWMGFHOWtJam9pYVc1amNtVnRaVzUwSW4wPSJdfQ==' },
                ],
            });

            // Expect redeemInfo to be unset.
            redeemInfo = provider['redeemInfo'];
            expect(redeemInfo).toBeNull();

            // Expect one token to be consumed.
            const storedTokens = provider['getStoredTokens']();
            expect(storedTokens.map((token) => token.toString())).toEqual(
                tokens.slice(1).map((token) => token.toString()),
            );

            expect(updateIcon.mock.calls.length).toBe(2);
            expect(updateIcon).toHaveBeenLastCalledWith((tokens.length - 1).toString());
            expect(navigateUrl).not.toHaveBeenCalled();
        });

        test('valid response without tokens', () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new HcaptchaProvider(storage, { updateIcon, navigateUrl });
            let result;

            provider['setStoredTokens']([]);
            expect(updateIcon.mock.calls.length).toBe(1);
            expect(updateIcon).toHaveBeenCalledWith('0');

            const bodyDetails: chrome.webRequest.WebRequestBodyDetails = validDetails;
            result = provider.handleBeforeRequest(bodyDetails);

            const headDetails: any = {
                ...validDetails,
                requestHeaders: [],
            };
            delete headDetails.requestBody;

            result = provider.handleBeforeSendHeaders(<chrome.webRequest.WebRequestHeadersDetails>headDetails);
            expect(result).toBeUndefined();

            expect(updateIcon.mock.calls.length).toBe(2);
            expect(updateIcon).toHaveBeenLastCalledWith('0');
            expect(navigateUrl).not.toHaveBeenCalled();
        });

        test('no response from an issuing domain (hostname)', () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new HcaptchaProvider(storage, { updateIcon, navigateUrl });
            const tokens = [new Token(), new Token(), new Token()];
            provider['setStoredTokens'](tokens);

            expect(updateIcon.mock.calls.length).toBe(1);
            expect(updateIcon).toHaveBeenCalledWith(tokens.length.toString());

            const details: chrome.webRequest.WebRequestBodyDetails = {
                ...validDetails,
                requestBody: {
                    formData: {
                        ...validDetails.requestBody!.formData!,
                        host: ['www.hcaptcha.com'],
                    },
                },
            };
            const result = provider.handleBeforeRequest(details);
            expect(result).toBeUndefined();

            expect(updateIcon.mock.calls.length).toBe(1);
            expect(navigateUrl).not.toHaveBeenCalled();
        });

        test('no response from an issuing domain (sitekey in body)', () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new HcaptchaProvider(storage, { updateIcon, navigateUrl });
            const tokens = [new Token(), new Token(), new Token()];
            provider['setStoredTokens'](tokens);

            expect(updateIcon.mock.calls.length).toBe(1);
            expect(updateIcon).toHaveBeenCalledWith(tokens.length.toString());

            const details: chrome.webRequest.WebRequestBodyDetails = {
                ...validDetails,
                requestBody: {
                    formData: {
                        ...validDetails.requestBody!.formData!,
                        sitekey: ['00000000-0000-0000-0000-000000000000'],
                    },
                },
            };
            const result = provider.handleBeforeRequest(details);
            expect(result).toBeUndefined();

            expect(updateIcon.mock.calls.length).toBe(1);
            expect(navigateUrl).not.toHaveBeenCalled();
        });

        test('no response from an issuing domain (sitekey in querystring)', () => {
            const storage = new StorageMock();
            const updateIcon = jest.fn();
            const navigateUrl = jest.fn();

            const provider = new HcaptchaProvider(storage, { updateIcon, navigateUrl });
            const tokens = [new Token(), new Token(), new Token()];
            provider['setStoredTokens'](tokens);

            expect(updateIcon.mock.calls.length).toBe(1);
            expect(updateIcon).toHaveBeenCalledWith(tokens.length.toString());

            const details: chrome.webRequest.WebRequestBodyDetails = {
                ...validDetails,
                url: validDetails.url.replace(/\?s=.*$/, '?s=00000000-0000-0000-0000-000000000000'),
            };
            const result = provider.handleBeforeRequest(details);
            expect(result).toBeUndefined();

            expect(updateIcon.mock.calls.length).toBe(1);
            expect(navigateUrl).not.toHaveBeenCalled();
        });
    });
});
