/**
 * Integrations tests for when headers are sent by the browser
 *
 * @author: Alex Davidson
 * @author: Drazen Urch
 */

import each from "jest-each";

const workflow = workflowSet();

/**
 * Functions/variables
 */
const EXAMPLE_HREF = "https://example.com";
const CAPTCHA_HREF = "https://captcha.website";
const EXAMPLE_RECAPTCHA_KEY = "g-recaptcha-response";
const EXAMPLE_RECAPTCHA_RESPONSE = "03AOLTBLSOy6WHlUbY1NHUPJ16g4rgCLbxjIDfkPpuXqzJs1Kxlvn_r8_1bSTddulO2D0Syy_Cq0kEATE5qsUZa8aUzX_HR74BnBH_4pTjg8YlgKYWx_Qgi-";
const EXAMPLE_SUFFIX = "/?__cf_chl_captcha_tk__=216fe230433131e3106752ed2c9555fd296321ad-1574861306-0-AQJlysCcbc7cU5uLtUADvfk13pDWxIV62To0kYVo6YQ3RhYM1LTZUJhSyCFU2RPW-WSPT1ElOSxIjzLFYBWoE6mnQ-fe2lL-fsZQhB_3466PKMLHCy9Hnzl6p-EqPWAXDwStqISWVSdMtKeKDFU52ySlpLs-Q_R5lY8qraCgjym-6gAHYBHZm9IRLNM9T48xUrd8Zs2pyLBRZRdb3ZUZH9Rb40wSVVVNZz0Fh6jLzjjkYemQb43LYrc-cN_GdeVgCcLjo0CBTAvCZUHm0D5c1cX8m1-OBmxO6T0dgcIrgFa_";
const CAPTCHA_BYPASS_SUFFIX = "&captcha-bypass=true";
const beforeRequest = workflow.__get__("beforeRequest");
const sendXhrSignReq = workflow.__get__("sendXhrSignReq");
const getBigNumFromBytes = workflow.__get__("getBigNumFromBytes");
const createVerificationXHR = workflow.__get__("createVerificationXHR");
const retrieveCommitments = workflow.__get__("retrieveCommitments");
const validateResponse = workflow.__get__("validateResponse");
const validateAndStoreTokens = workflow.__get__("validateAndStoreTokens");
const parseIssueResp = workflow.__get__("parseIssueResp");
const parseSigString = workflow.__get__("parseSigString");
const setConfig = workflow.__get__("setConfig");
const getCachedCommitments = workflow.__get__("getCachedCommitments");
const cacheCommitments = workflow.__get__("cacheCommitments");
const checkVersion = workflow.__get__("checkVersion");

const PPConfigs = workflow.__get__("PPConfigs");

let details;
let url;
let configId;

beforeEach(() => {
    clearLocalStorage();
    setMock(bypassTokensCount(configId), 2);

    details = {
        method: "GET",
        requestHeaders: [],
        requestId: "212",
        tabId: "101",
        requestBody: {
            formData: {},
        },
    };
    details.requestBody.formData[EXAMPLE_RECAPTCHA_KEY] = EXAMPLE_RECAPTCHA_RESPONSE;
    url = new URL(EXAMPLE_HREF);
    setTimeSinceLastResp(Date.now());
    // Some tests make sense only for CF
    configId = configId === undefined ? 1 : configId;
    setConfig(configId); // set the active config
    workflow.__set__("issueActionUrls", () => [LISTENER_URLS]);
    workflow.__set__("getCommitmentsKey", () => testPubKey);
});

/**
 * Tests
 */
describe("commitments parsing and caching", () => {
    beforeEach(() => {
        setXHR(mockXHRCommitments, workflow);
    });

    test("version not available", () => {
        const xhr = createVerificationXHR(); // this usually takes params
        expect(
            jest.fn(() => retrieveCommitments(xhr, "-1.00"))
        ).toThrow("Retrieved version");
    });

    test("bad public key", () => {
        const xhr = createVerificationXHR(); // this usually takes params
        workflow.__set__("getCommitmentsKey", () => "badPublicKey");
        expect(
            jest.fn(() => retrieveCommitments(xhr, "2.0-sig-ok"))
        ).toThrow("Failed on parsing public key");
    });

    test("version not available", () => {
        const xhr = createVerificationXHR(); // this usually takes params
        expect(
            jest.fn(() => retrieveCommitments(xhr))
        ).toThrow("Retrieved version");
    });

    test("parse correctly (v1.0)", () => {
        const xhr = createVerificationXHR(); // this usually takes params
        const commitments = retrieveCommitments(xhr, "1.0");
        expect(testG === commitments.G).toBeTruthy();
        expect(testH === commitments.H).toBeTruthy();
    });

    test("parse correctly (sig-ok)", () => {
        const xhr = createVerificationXHR(); // this usually takes params
        const commitments = retrieveCommitments(xhr, "2.0-sig-ok");
        expect(testSigG === commitments.G).toBeTruthy();
        expect(testSigH === commitments.H).toBeTruthy();
    });

    test("parse correctly (prod v1.01)", () => {
        const xhr = createVerificationXHR(); // this usually takes params
        workflow.__set__("getCommitmentsKey", () => prodPubKey);
        const commitments = retrieveCommitments(xhr, "1.01");
        expect(workersG === commitments.G).toBeTruthy();
        expect(workersH === commitments.H).toBeTruthy();
    });

    test("parse correctly (dev)", () => {
        workflow.__with__({dev: () => true})(() => {
            const xhr = createVerificationXHR(); // this usually takes params
            const version = checkVersion("1.1");
            const commitments = retrieveCommitments(xhr, version);
            expect(testDevG === commitments.G).toBeTruthy();
            expect(testDevH === commitments.H).toBeTruthy();
        });
    });

    test("parse correctly (hkdf)", () => {
        const xhr = createVerificationXHR(); // this usually takes params
        const commitments = retrieveCommitments(xhr, "hkdf");
        expect(hkdfG === commitments.G).toBeTruthy();
        expect(hkdfH === commitments.H).toBeTruthy();
    });

    test("caching commitments", () => {
        cacheCommitments("1.0", testG, testH);
        const cached10 = getCachedCommitments("1.0");
        expect(cached10.G === testG).toBeTruthy();
        expect(cached10.H === testH).toBeTruthy();
        const cached11 = getCachedCommitments("1.1");
        expect(cached11).toBeFalsy();
        setConfig(0);
        expect(getCachedCommitments("1.0")).toBeFalsy();
    });

    test("caching commitments (hkdf)", () => {
        cacheCommitments("hkdf", hkdfG, hkdfH);
        const cachedHkdf = getCachedCommitments("hkdf");
        expect(cachedHkdf.G === hkdfG).toBeTruthy();
        expect(cachedHkdf.H === hkdfH).toBeTruthy();
        setConfig(0);
        expect(getCachedCommitments("hkdf")).toBeFalsy();
    });

    test("error-free empty cache", () => {
        clearCachedCommitmentsMock();
        expect(getCachedCommitments).not.toThrowError();
    });

    test("malformed commitments signature", () => {
        const xhr = createVerificationXHR(); // this usually takes params
        expect(
            jest.fn(() => retrieveCommitments(xhr, "2.0-sig-bad"))
        ).toThrow("Failed on parsing commitment signature");
    });

    test("signature doesn't verify", () => {
        const xhr = createVerificationXHR(); // this usually takes params
        expect(
            jest.fn(() => retrieveCommitments(xhr, "2.0-sig-fail"))
        ).toThrow("Invalid commitment");
    });

    test("expired commitments", () => {
        const xhr = createVerificationXHR(); // this usually takes params
        expect(
            jest.fn(() => retrieveCommitments(xhr, "2.0-expired"))
        ).toThrow("Commitments expired in");
    });
});

each(PPConfigs().filter((config) => config.id > 0).map((config) => [config.id]))
    .describe("config_id = %i signing request is cancelled", (configId) => {
        test("signing off", () => {
            workflow.__with__({doSign: () => false})(() => {
                const b = beforeRequest(details, url);
                expect(b).toBeFalsy();
            });
        });
        test("signing not activated", () => {
            workflow.__set__("readySign", false);
            const b = beforeRequest(details, url);
            expect(b).toBeFalsy();
        });
        test("url is not captcha request", () => {
            const b = beforeRequest(details, url);
            expect(b).toBeFalsy();
        });
        test("variables are reset", () => {
            setSpentHostsMock(url.host, true);
            setTimeSinceLastResp(0);
            const b = beforeRequest(details, url);
            expect(getSpentHostsMock(url.host)).toBeFalsy();
            expect(b).toBeFalsy();
        });
        test("body does not contain CAPTCHA solution", () => {
            const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX + CAPTCHA_BYPASS_SUFFIX);
            details.requestBody = {};
            const b = beforeRequest(details, newUrl);
            expect(b).toBeFalsy();
        });
        test("already processed", () => {
            const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX + CAPTCHA_BYPASS_SUFFIX);
            const b = beforeRequest(details, newUrl);
            expect(b).toBeFalsy();
        });
        test("already sent", () => {
            const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
            setSpentHostsMock(newUrl.host, true);
            const b = beforeRequest(details, url);
            expect(b).toBeFalsy();
        });
    });
each(PPConfigs().filter((config) => config.id > 0).map((config) => [config.id]))
    .describe("config_id = %i, test sending sign requests", (configId) => {
        test("incorrect config id", () => {
            function tryRun() {
                workflow.__with__({CONFIG_ID: () => 3})(() => {
                    beforeRequest(details, newUrl);
                });
            }
            const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
            expect(tryRun).toThrowError("Incorrect config ID specified");
        });

        test("test that true is returned", () => {
            workflow.__with__({readySign: true})(() => {
                const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                const b = beforeRequest(details, newUrl);
                expect(b).toBeTruthy();
                expect(b.xhr).toBeTruthy();
                if (configId === 1) {
                    expect(b.xhr.send).toBeCalledWith(expect.stringContaining(`${EXAMPLE_RECAPTCHA_KEY}=${EXAMPLE_RECAPTCHA_RESPONSE}`));
                    expect(b.xhr.send).toBeCalledWith(expect.stringContaining("blinded-tokens="));
                }
            });
        });

        test("bad status does not sign", () => {
            setTimeSinceLastResp(0); // reset the variables
            const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
            workflow.__with__({"readySign": true, "XMLHttpRequest": mockXHRBadStatus})(() => {
                const b = beforeRequest(details, newUrl);
                expect(b).toBeTruthy();
                const xhr = b.xhr;
                if (configId === 1) {
                    expect(xhr.send).toBeCalledWith(expect.stringContaining(`${EXAMPLE_RECAPTCHA_KEY}=${EXAMPLE_RECAPTCHA_RESPONSE}`));
                    expect(xhr.send).toBeCalledWith(expect.stringContaining("blinded-tokens="));
                }
                xhr.onreadystatechange();
                expect(validateRespMock).not.toBeCalled();
                expect(updateIconMock).toBeCalledTimes(2);
                expect(updateBrowserTabMock).not.toBeCalled();
            });
        });

        test("bad readyState does not sign", () => {
            setTimeSinceLastResp(0); // reset the variables
            const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
            workflow.__with__({"readySign": true, "XMLHttpRequest": mockXHRBadReadyState})(() => {
                const b = beforeRequest(details, newUrl);
                expect(b).toBeTruthy();
                const xhr = b.xhr;
                if (configId === 1) {
                    expect(xhr.send).toBeCalledWith(expect.stringContaining(`${EXAMPLE_RECAPTCHA_KEY}=${EXAMPLE_RECAPTCHA_RESPONSE}`));
                    expect(xhr.send).toBeCalledWith(expect.stringContaining("blinded-tokens="));
                }
                xhr.onreadystatechange();
                expect(validateRespMock).not.toBeCalled();
                expect(updateIconMock).toBeCalledTimes(2);
                expect(updateBrowserTabMock).not.toBeCalled();
            });
        });

        test("too many tokens does not sign", () => {
            // Always test CF here due to mock data being available
            if (configId === 1) {
                workflow.__with__({readySign: true, XMLHttpRequest: mockXHRGood})(() => {
                    function run() {
                        const b = beforeRequest(details, newUrl);
                        const xhr = b.xhr;
                        xhr.onreadystatechange();
                    }
                    setTimeSinceLastResp(0); // reset the variables
                    setMock(bypassTokensCount(configId), 400);
                    const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);

                    expect(run).toThrowError("upper bound");
                    expect(validateRespMock).not.toBeCalled();
                    expect(updateIconMock).toBeCalledTimes(3);
                    expect(updateBrowserTabMock).not.toBeCalled();
                });
            }
        });

        test("correct XHR response triggers validation", () => {
            workflow.__with__({"validateResponse": validateRespMock, "XMLHttpRequest": mockXHRGood})(() => {
                function run() {
                    const request = "";
                    const xhrInfo = {newUrl: newUrl, requestBody: "blinded-tokens=" + request, tokens: ""};
                    const xhr = sendXhrSignReq(xhrInfo, newUrl, details.tabId);
                    xhr.responseText = "";
                    xhr.onreadystatechange();
                }
                setTimeSinceLastResp(0); // reset the variables
                setMock(bypassTokensCount(configId), 0);
                const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                expect(run).not.toThrow();
                expect(validateRespMock).toBeCalled();
                expect(updateIconMock).toBeCalledTimes(2);
            });
        });
    });

describe("test validating response", () => {
    describe("test response format errors", () => {
        test("invalid signature response format does not sign", () => {
            function run() {
                setTimeSinceLastResp(0); // reset the variables
                workflow.__with__({signResponseFMT: () => "bad_fmt"})(() => {
                    const tabId = details.tabId;
                    validateResponse(url, tabId, "", "");
                });
            }
            expect(run).toThrowError("invalid signature response format");
            expect(updateIconMock).toBeCalledTimes(1);
            expect(updateBrowserTabMock).not.toBeCalled();
        });

        test("invalid data format", () => {
            function run() {
                setTimeSinceLastResp(0); // reset the variables
                const tabId = details.tabId;
                validateResponse(url, tabId, "bad-set-of-data", "");
            }
            expect(run).toThrowError("signature response invalid");
            expect(updateIconMock).toBeCalledTimes(1);
            expect(updateBrowserTabMock).not.toBeCalled();
        });
    });

    describe("parse data format", () => {
        test("parse in old format", () => {
            const issueData = ["sig1", "sig2", "sig3", "proof"];
            const out = parseIssueResp(issueData);
            expect(out.signatures[0] === "sig1").toBeTruthy();
            expect(out.signatures[2] === "sig3").toBeTruthy();
            expect(out.proof === "proof").toBeTruthy();
            expect(out.prng === "shake");
            expect(out.version).toBeFalsy();
        });

        test("parse in new JSON format (without prng)", () => {
            const issueData = {
                sigs: ["sig1", "sig2", "sig3"],
                proof: "proof",
                version: "1.0",
            };
            const out = parseIssueResp(issueData);
            expect(out.signatures[0] === "sig1").toBeTruthy();
            expect(out.signatures[2] === "sig3").toBeTruthy();
            expect(out.proof === "proof").toBeTruthy();
            expect(out.prng === "shake");
            expect(out.version).toBeTruthy();
        });

        test("parse in new JSON format (with prng)", () => {
            const issueData = {
                sigs: ["sig1", "sig2", "sig3"],
                proof: "proof",
                version: "1.0",
                prng: "hkdf",
            };
            const out = parseIssueResp(issueData);
            expect(out.signatures[0] === "sig1").toBeTruthy();
            expect(out.signatures[2] === "sig3").toBeTruthy();
            expect(out.proof === "proof").toBeTruthy();
            expect(out.prng === "hkdf");
            expect(out.version).toBeTruthy();
        });
    });

    describe("test validation and storage", () => {
        beforeAll(() => {
            setXHR(mockXHRCommitments, workflow);
        });

        goodResponses.forEach((element) => {
            let commVersion;
            let testTokenData;
            let G;
            let H;
            let pubKey = testPubKey;
            let before;
            let after;
            let version;
            let testUrl;
            beforeEach(() => {
                before = undefined;
                after = undefined;
                version = undefined;
                testUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                if (element.name.includes("hkdf")) {
                    commVersion = "hkdf";
                    if (element.name.includes("compressed")) {
                        testTokenData = testTokensHkdfCompressed;
                    } else {
                        testTokenData = testTokensHkdf;
                    }
                    G = hkdfG;
                    H = hkdfH;
                } else if (element.name.includes("workers")) {
                    G = workersG;
                    H = workersH;
                    testTokenData = testTokensWorker;
                    commVersion = "1.01";
                    pubKey = prodPubKey;
                } else {
                    commVersion = "1.0";
                    testTokenData = testTokens;
                    G = testG;
                    H = testH;
                    workflow.__set__("storedCommitments", () => {
                        return {
                            "1.0": {
                                G: testG,
                                H: testH,
                            },
                        };
                    });
                }
            });

            function checkCache(version) {
                const cache = getCachedCommitments(version);
                if (version !== "1.0") {
                    expect(cache.G === G).toBeTruthy();
                    expect(cache.H === H).toBeTruthy();
                } else {
                    expect(cache).toBeFalsy();
                }
            }

            function oldVersions(tokens, out) {
                before = getMock(bypassTokensCount(1));
                const xhr = validateAndStoreTokens(testUrl, details.tabId, tokens, out);
                expect(xhr).toBeFalsy();
                after = getMock(bypassTokensCount(1));
            }

            function newVersions(tokens, out) {
                const xhr = validateAndStoreTokens(testUrl, details.tabId, tokens, out);
                expect(xhr).toBeTruthy();
                expect(xhr.send).toBeCalledTimes(1);
                before = getMock(bypassTokensCount(1));
                xhr.onreadystatechange();
                after = getMock(bypassTokensCount(1));
            }

            test(`test store tokens: ${element.name}`, () => {
                function run() {
                    workflow.__set__("getCommitmentsKey", () => pubKey);
                    const tokens = [];
                    for (let i = 0; i < testTokenData.length; i++) {
                        tokens[i] = {data: testTokenData[i].data, point: sec1DecodeFromBytes(testTokenData[i].point), blind: getBigNumFromBytes(testTokenData[i].blind)};
                    }
                    const out = parseRespString(element.string);
                    commVersion === "1.0" ? oldVersions(tokens, out) : newVersions(tokens, out);
                    version = checkVersion(out.version);
                }
                setTimeSinceLastResp(0); // reset the variables
                setMock(bypassTokensCount(1), 0);
                expect(consoleMock.error).not.toBeCalled();
                expect(run).not.toThrow();
                expect(updateIconMock).toBeCalledTimes(3);
                expect(updateBrowserTabMock).toBeCalled();
                expect(after === before + testTokenData.length).toBeTruthy();
                expect(getSpendFlagMock(testUrl.host)).toBeTruthy();
                checkCache(version);
            });

            test(`correct verify for cached commitments: ${element.name}`, () => {
                cacheCommitments(commVersion, G, H);
                expect(getCachedCommitments(commVersion).G === G).toBeTruthy();
                expect(getCachedCommitments(commVersion).H === H).toBeTruthy();
                function run() {
                    workflow.__set__("getCommitmentsKey", () => pubKey);
                    const tokens = [];
                    for (let i = 0; i < testTokenData.length; i++) {
                        tokens[i] = {token: testTokenData[i].data, point: sec1DecodeFromBytes(testTokenData[i].point), blind: getBigNumFromBytes(testTokenData[i].blind)};
                    }
                    const out = parseRespString(element.string);
                    before = getMock(bypassTokensCount(1));
                    const xhr = validateAndStoreTokens(testUrl, details.tabId, tokens, out);
                    expect(xhr).toBeFalsy(); // because the commitments are cached, the xhr should not be generated.
                    after = getMock(bypassTokensCount(1));
                    version = checkVersion(out.version);
                }
                setTimeSinceLastResp(0); // reset the variables
                setMock(bypassTokensCount(1), 0);
                const testUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                expect(consoleMock.error).not.toBeCalled();
                expect(run).not.toThrow();
                expect(updateIconMock).toBeCalledTimes(3);
                expect(updateBrowserTabMock).toBeCalled();
                expect(after === before + testTokenData.length).toBeTruthy();
                expect(getSpendFlagMock(testUrl.host)).toBeTruthy();
                const cache = getCachedCommitments(version);
                expect(cache.G === G).toBeTruthy();
                expect(cache.H === H).toBeTruthy();
            });

            test(`correct verify when cached commitments are bad: ${element.name}`, () => {
                // construct corrupted commitments
                const commStruct = {};
                commStruct[commVersion] = {L: G, H: H};
                setMock(CACHED_COMMITMENTS_STRING, JSON.stringify(commStruct));
                function run() {
                    workflow.__set__("getCommitmentsKey", () => pubKey);
                    const tokens = [];
                    for (let i = 0; i < testTokenData.length; i++) {
                        tokens[i] = {token: testTokenData[i].data, point: sec1DecodeFromBytes(testTokenData[i].point), blind: getBigNumFromBytes(testTokenData[i].blind)};
                    }
                    const out = parseRespString(element.string);
                    commVersion === "1.0" ? oldVersions(tokens, out) : newVersions(tokens, out);
                    version = checkVersion(out.version);
                }
                setTimeSinceLastResp(0); // reset the variables
                setMock(bypassTokensCount(1), 0);
                expect(consoleMock.error).not.toBeCalled();
                expect(run).not.toThrow();
                commVersion === "1.0" ? expect(consoleMock.warn).not.toBeCalled() : expect(consoleMock.warn).toBeCalled();
                expect(updateIconMock).toBeCalledTimes(3);
                expect(updateBrowserTabMock).toBeCalled();
                expect(after === before + testTokenData.length).toBeTruthy();
                expect(getSpendFlagMock(testUrl.host)).toBeTruthy();
                // bad commitments are not removed if using version 1.0
                if (commVersion !== "1.0") {
                    checkCache(version);
                }
            });

            test(`test store tokens for captcha.website: ${element.name}`, () => {
                function run() {
                    workflow.__set__("getCommitmentsKey", () => pubKey);
                    const tokens = [];
                    for (let i = 0; i < testTokenData.length; i++) {
                        tokens[i] = {data: testTokenData[i].data, point: sec1DecodeFromBytes(testTokenData[i].point), blind: getBigNumFromBytes(testTokenData[i].blind)};
                    }
                    const out = parseRespString(element.string);
                    commVersion === "1.0" ? oldVersions(tokens, out) : newVersions(tokens, out);
                    version = checkVersion(out.version);
                }
                setTimeSinceLastResp(0); // reset the variables
                setMock(bypassTokensCount(1), 0);
                testUrl = new URL(CAPTCHA_HREF + EXAMPLE_SUFFIX);
                expect(consoleMock.error).not.toBeCalled();
                expect(run).not.toThrow();
                expect(updateIconMock).toBeCalledTimes(3);
                expect(updateBrowserTabMock).not.toBeCalled();
                expect(after === before + testTokenData.length).toBeTruthy();
                expect(getSpendFlagMock(testUrl.host)).toBeFalsy();
                checkCache(version);
            });

            test(`reloading off after sign: ${element.name}`, () => {
                testUrl = new URL(CAPTCHA_HREF + EXAMPLE_SUFFIX);
                function run() {
                    workflow.__set__("getCommitmentsKey", () => pubKey);
                    const tokens = [];
                    for (let i = 0; i < testTokenData.length; i++) {
                        tokens[i] = {data: testTokenData[i].data, point: sec1DecodeFromBytes(testTokenData[i].point), blind: getBigNumFromBytes(testTokenData[i].blind)};
                    }
                    const out = parseRespString(element.string);
                    commVersion === "1.0" ? oldVersions(tokens, out) : newVersions(tokens, out);
                    version = checkVersion(out.version);
                }
                setTimeSinceLastResp(0); // reset the variables
                setMock(bypassTokensCount(1), 0);
                workflow.__with__({"reloadOnSign": () => false})(() => {
                    testUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                    expect(consoleMock.error).not.toBeCalled();
                    expect(run).not.toThrow();
                    expect(updateIconMock).toBeCalledTimes(3);
                    expect(updateBrowserTabMock).not.toBeCalled();
                    expect(after === before + testTokenData.length).toBeTruthy();
                    expect(getSpendFlagMock(testUrl.host)).toBeFalsy();
                    checkCache(version);
                });
            });
        });

        describe("test parsing errors", () => {
            test("cannot decode point", () => {
                function run() {
                    const tokens = [];
                    for (let i = 0; i < testTokens.length; i++) {
                        tokens[i] = {data: testTokens[i].data, point: sec1DecodeFromBytes(testTokens[i].point), blind: getBigNumFromBytes(testTokens[i].blind)};
                    }
                    const out = parseRespString("signatures=WyJiYWRfcG9pbnQxIiwgImJhZF9wb2ludDIiXQ==");
                    const xhr = validateAndStoreTokens(newUrl, details.tabId, tokens, out);
                    xhr.onreadystatechange();
                }
                setTimeSinceLastResp(0); // reset the variables
                setMock(bypassTokensCount(configId), 0);
                const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                expect(run).toThrow();
                expect(updateIconMock).toBeCalledTimes(1);
                expect(updateBrowserTabMock).not.toBeCalled();
            });

            describe("DLEQ formatting errors", () => {
                test("proof is not JSON", () => {
                    function run() {
                        const tokens = [];
                        for (let i = 0; i < testTokens.length; i++) {
                            tokens[i] = {data: testTokens[i].data, point: sec1DecodeFromBytes(testTokens[i].point), blind: getBigNumFromBytes(testTokens[i].blind)};
                        }
                        const out = parseRespString(respBadJson);
                        const xhr = validateAndStoreTokens(newUrl, details.tabId, tokens, out);
                        xhr.onreadystatechange();
                    }
                    setTimeSinceLastResp(0); // reset the variables
                    setMock(bypassTokensCount(configId), 0);
                    const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                    expect(run).toThrow();
                    expect(updateIconMock).toBeCalledTimes(1);
                    expect(updateBrowserTabMock).not.toBeCalled();
                });

                test("proof has bad points", () => {
                    function run() {
                        const tokens = [];
                        for (let i = 0; i < testTokens.length; i++) {
                            tokens[i] = {data: testTokens[i].data, point: sec1DecodeFromBytes(testTokens[i].point), blind: getBigNumFromBytes(testTokens[i].blind)};
                        }
                        const out = parseRespString(respBadPoints);
                        const xhr = validateAndStoreTokens(newUrl, details.tabId, tokens, out);
                        xhr.onreadystatechange();
                    }
                    setTimeSinceLastResp(0); // reset the variables
                    setMock(bypassTokensCount(configId), 0);
                    const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                    expect(run).toThrow();
                    expect(updateIconMock).toBeCalledTimes(1);
                    expect(updateBrowserTabMock).not.toBeCalled();
                });

                test("proof should not verify (bad lengths)", () => {
                    function run() {
                        const tokens = [];
                        for (let i = 0; i < testTokensBadLength.length; i++) {
                            tokens[i] = {data: testTokens[i].data, point: sec1DecodeFromBytes(testTokens[i].point), blind: getBigNumFromBytes(testTokens[i].blind)};
                        }
                        const out = parseRespString(respBadProof);
                        const xhr = validateAndStoreTokens(newUrl, details.tabId, tokens, out);
                        xhr.onreadystatechange();
                    }
                    const consoleNew = {
                        error: jest.fn(),
                    };
                    workflow.__set__("console", consoleNew); // fake the console to check logs
                    setTimeSinceLastResp(0); // reset the variables
                    setMock(bypassTokensCount(configId), 0);
                    const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                    expect(run).toThrowError("Unable to verify DLEQ");
                    expect(consoleNew.error).not.toHaveBeenCalledWith(workflow.__get__("DIGEST_INEQUALITY_ERR"));
                    expect(updateIconMock).toBeCalledTimes(1);
                    expect(updateBrowserTabMock).not.toBeCalled();
                });

                test("proof should not verify", () => {
                    function run() {
                        const tokens = [];
                        for (let i = 0; i < testTokens.length; i++) {
                            tokens[i] = {data: testTokens[i].data, point: sec1DecodeFromBytes(testTokens[i].point), blind: getBigNumFromBytes(testTokens[i].blind)};
                        }
                        const out = parseRespString(respBadProof);
                        const xhr = validateAndStoreTokens(newUrl, details.tabId, tokens, out);
                        xhr.onreadystatechange();
                    }
                    const consoleNew = {
                        error: jest.fn(),
                    };
                    workflow.__set__("console", consoleNew); // fake the console to check logs
                    setTimeSinceLastResp(0); // reset the variables
                    setMock(bypassTokensCount(configId), 0);
                    const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                    expect(run).toThrowError("Unable to verify DLEQ");
                    expect(consoleNew.error).toHaveBeenCalledWith(workflow.__get__("DIGEST_INEQUALITY_ERR"));
                    expect(updateIconMock).toBeCalledTimes(1);
                    expect(updateBrowserTabMock).not.toBeCalled();
                });
            });
        });
    });
});

function parseRespString(respText) {
    return parseIssueResp(JSON.parse(parseSigString(respText)));
}

function getSpentHostsMock(key) {
    const spentHosts = workflow.__get__("spentHosts", spentHosts);
    return spentHosts[key];
}
