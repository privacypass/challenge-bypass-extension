import { HcaptchaProvider, IssueInfo } from './hcaptcha';
import Token from '../token';
import { jest } from '@jest/globals';

class TestHcaptchaProvider extends HcaptchaProvider {
    setIssueInfo(info: IssueInfo): void {
        this.issueInfo = info;
    }
}

class StorageMock {
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

    const provider = new HcaptchaProvider(storage, { updateIcon, navigateUrl });
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

    const provider = new HcaptchaProvider(storage, { updateIcon, navigateUrl });
    const tokens = [new Token(), new Token()];
    provider['setStoredTokens'](tokens);
    const tok = storage.store.get('tokens');
    expect(tok).toBeDefined();
    if (tok !== undefined) {
        const storedTokens = JSON.parse(tok);
        expect(storedTokens).toEqual(tokens.map((token) => token.toString()));
    }
});

describe('getBadgeText', () => {
    test('extension still has 2 tokens stored', () => {
        const storage = new StorageMock();
        const updateIcon = jest.fn();
        const navigateUrl = jest.fn();

        const provider = new HcaptchaProvider(storage, { updateIcon, navigateUrl });
        const tokens = [new Token(), new Token()];
        provider['setStoredTokens'](tokens);
        const text = provider['getBadgeText']();
        expect(text).toBe('2');
    });
    test('storage has no tokens left', () => {
        const storage = new StorageMock();
        const updateIcon = jest.fn();
        const navigateUrl = jest.fn();

        const provider = new HcaptchaProvider(storage, { updateIcon, navigateUrl });
        const text = provider['getBadgeText']();
        expect(text).toBe('0');
    });
});

describe('new tokens', () => {
    describe('handleHeadersReceived', () => {
        const storage = new StorageMock();
        const updateIcon = jest.fn();
        const navigateUrl = jest.fn();
        const validDetails = {
            url: 'https://hcaptcha.com/checkcaptcha/00000000-0000-0000-0000-000000000000/data',
            requestId: 'xxx',
            frameId: 1,
            parentFrameId: 1,
            tabId: 1,
            type: 'main_frame' as chrome.webRequest.ResourceType,
            timeStamp: 1,
            method: 'POST',
            statusCode: 200,
            statusLine: 'HTTP/1.1 200 OK',
        };
        const forbiddenDetails = {
            ...validDetails,
            statusCode: 403,
            statusLine: 'HTTP/1.1 403 Forbidden',
        };
        const wrongUrlFormatDetails = {
            ...validDetails,
            url: 'https://example.com',
        };

        test('do not try to get tokens after a captcha failure', () => {
            const provider = new TestHcaptchaProvider(storage, { updateIcon, navigateUrl });
            provider.setIssueInfo({
                newUrl: forbiddenDetails.url,
                tabId: forbiddenDetails.tabId,
            });
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const issueToken = jest.spyOn(TestHcaptchaProvider.prototype as any, 'issue');
            // eslint-disable-next-line @typescript-eslint/no-empty-function
            issueToken.mockImplementation(async () => {});

            provider.handleHeadersReceived(forbiddenDetails);
            expect(provider['issueInfo']).not.toBeNull();
            expect(issueToken).toBeCalledTimes(0);
        });

        test('do not try to get tokens on a wrong url', () => {
            const provider = new TestHcaptchaProvider(storage, { updateIcon, navigateUrl });
            provider.setIssueInfo({
                newUrl: wrongUrlFormatDetails.url,
                tabId: wrongUrlFormatDetails.tabId,
            });
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const issueToken = jest.spyOn(TestHcaptchaProvider.prototype as any, 'issue');
            // eslint-disable-next-line @typescript-eslint/no-empty-function
            issueToken.mockImplementation(async () => {});

            provider.handleHeadersReceived(wrongUrlFormatDetails);
            expect(provider['issueInfo']).not.toBeNull();
            expect(issueToken).toBeCalledTimes(0);
        });

        test('do not try to get tokens if issueInfo is null', () => {
            const provider = new TestHcaptchaProvider(storage, { updateIcon, navigateUrl });
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const issueToken = jest.spyOn(TestHcaptchaProvider.prototype as any, 'issue');
            // eslint-disable-next-line @typescript-eslint/no-empty-function
            issueToken.mockImplementation(async () => {});

            provider.handleHeadersReceived(validDetails);
            expect(provider['issueInfo']).toBeNull();
            expect(issueToken).toBeCalledTimes(0);
        });

        test('get tokens after successful captcha response', () => {
            const provider = new TestHcaptchaProvider(storage, { updateIcon, navigateUrl });
            provider.setIssueInfo({
                newUrl: validDetails.url,
                tabId: validDetails.tabId,
            });
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const issueToken = jest.spyOn(TestHcaptchaProvider.prototype as any, 'issue');
            // eslint-disable-next-line @typescript-eslint/no-empty-function
            issueToken.mockImplementation(async () => {});

            provider.handleHeadersReceived(validDetails);
            // Expect issueInfo to be null after calling issuer function.
            expect(provider['issueInfo']).toBeNull();
            expect(issueToken).toBeCalledWith(validDetails.url);
            expect(issueToken).toBeCalledTimes(1);
        });
    });
});
