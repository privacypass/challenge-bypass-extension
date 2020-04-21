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
const EXAMPLE_HREF = "https://example.com/";
const CAPTCHA_HREF = "https://captcha.website";
const CAPTCHA_KEYS = ["g-recaptcha-response", "h-captcha-response"];
const EXAMPLE_RECAPTCHA_RESPONSE = "03AOLTBLSOy6WHlUbY1NHUPJ16g4rgCLbxjIDfkPpuXqzJs1Kxlvn_r8_1bSTddulO2D0Syy_Cq0kEATE5qsUZa8aUzX_HR74BnBH_4pTjg8YlgKYWx_Qgi-";
const EXAMPLE_SUFFIX = "?__cf_chl_captcha_tk__=216fe230433131e3106752ed2c9555fd296321ad-1574861306-0-AQJlysCcbc7cU5uLtUADvfk13pDWxIV62To0kYVo6YQ3RhYM1LTZUJhSyCFU2RPW-WSPT1ElOSxIjzLFYBWoE6mnQ-fe2lL-fsZQhB_3466PKMLHCy9Hnzl6p-EqPWAXDwStqISWVSdMtKeKDFU52ySlpLs-Q_R5lY8qraCgjym-6gAHYBHZm9IRLNM9T48xUrd8Zs2pyLBRZRdb3ZUZH9Rb40wSVVVNZz0Fh6jLzjjkYemQb43LYrc-cN_GdeVgCcLjo0CBTAvCZUHm0D5c1cX8m1-OBmxO6T0dgcIrgFa_";
const OLD_EXAMPLE_SUFFIX = "cdn-cgi/l/chk_captcha?id=4716480f5bb534e8&g-recaptcha-response=03AMGVjXh24S6n8-HMQadfr8AmSr-2i87s1TTWUrhfnrIcti9hw1DigphUtiZzhU5R44VlJ3CmoH1W6wZaqde7iJads2bFaErY2bok29QfgZrbhO8q6UBbwLMkVlZ803M1UyDYhA9xYJqLR4kVtKhrHkDsUEKN4vXKc3CNxQpysmvdTqdt31Lz088ptkkksGLzRluDu-Np11ER6NX8XaH2S4iwIR823r3txm4eaMoEeoLfOD5S_6WHD5RhH0B7LRa_l7Vp5ksEB-0vyHQPLQQLOYixrC_peP3dG3dnaTY5UcUAUxZK4E74glzCu2PyRpKNnQ9akFz-niWiFCY0z-cuJeOArMvGOQCC9Q";
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
const getConfigName = workflow.__get__("getConfigName");
const cachedCommitmentsKey = workflow.__get__("cachedCommitmentsKey");
const cacheCommitments = workflow.__get__("cacheCommitments");
const checkVersion = workflow.__get__("checkVersion");
const setReadyIssue = workflow.__get__("setReadyIssue");

const PPConfigs = workflow.__get__("PPConfigs");

let details;
let url;
let configId;

// fake console
workflow.__set__("console", consoleMock);

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

    url = new URL(EXAMPLE_HREF);
    setTimeSinceLastResp(Date.now());
    // Some tests make sense only for CF
    configId = configId === undefined ? 1 : configId;
    setConfig(configId); // set the active config
    workflow.__set__("issueActionUrls", () => [LISTENER_URLS]);
    workflow.__set__("getVerificationKey", () => testPubKey);
});

/**
 * Tests
 */
CAPTCHA_KEYS.forEach((captchaKey) => {
    describe(`run tests with captchaKey: ${captchaKey}`, () => {
        beforeEach(() => {
            details.requestBody.formData[captchaKey] = EXAMPLE_RECAPTCHA_RESPONSE;
            if (captchaKey == "h-captcha-response") {
                details.requestBody.formData["cf_captcha_kind"] = "h";
            }
        });

        describe(`commitments parsing and caching`, () => {
            beforeEach(() => {
                setXHR(mockXHRCommitments, workflow);
            });

            test("version not available", () => {
                const xhr = createVerificationXHR(); // this usually takes params
                const provider = getConfigName(configId);
                const config = JSON.parse(xhr.responseText)[provider];
                expect(
                    jest.fn(() => retrieveCommitments(configId, config, "-1.00")),
                ).toThrow("Retrieved version");
            });

            test("bad public key", () => {
                const xhr = createVerificationXHR(); // this usually takes params
                workflow.__set__("getVerificationKey", () => "badPublicKey");
                const provider = getConfigName(configId);
                const config = JSON.parse(xhr.responseText)[provider];
                expect(
                    jest.fn(() => retrieveCommitments(configId, config, "2.0-sig-ok")),
                ).toThrow("Failed on parsing public key");
            });

            test("version not available", () => {
                const xhr = createVerificationXHR(); // this usually takes params
                const provider = getConfigName(configId);
                const config = JSON.parse(xhr.responseText)[provider];
                expect(
                    jest.fn(() => retrieveCommitments(configId, config)),
                ).toThrow("Retrieved version");
            });

            test("parse correctly (v1.0)", () => {
                const xhr = createVerificationXHR(); // this usually takes params
                const provider = getConfigName(configId);
                const config = JSON.parse(xhr.responseText)[provider];
                const commitments = retrieveCommitments(configId, config, "1.0");
                expect(testG === commitments.G).toBeTruthy();
                expect(testH === commitments.H).toBeTruthy();
            });

            test("parse correctly (sig-ok)", () => {
                const xhr = createVerificationXHR(); // this usually takes params
                const provider = getConfigName(configId);
                const config = JSON.parse(xhr.responseText)[provider];
                const commitments = retrieveCommitments(configId, config, "2.0-sig-ok");
                expect(testSigG === commitments.G).toBeTruthy();
                expect(testSigH === commitments.H).toBeTruthy();
            });

            test("parse correctly (dev)", () => {
                workflow.__with__({dev: () => true})(() => {
                    const xhr = createVerificationXHR(); // this usually takes params
                    const version = checkVersion(configId, "1.1");
                    const provider = getConfigName(configId);
                    const config = JSON.parse(xhr.responseText)[provider];
                    const commitments = retrieveCommitments(configId, config, version);
                    expect(testDevG === commitments.G).toBeTruthy();
                    expect(testDevH === commitments.H).toBeTruthy();
                });
            });

            test("parse correctly (hkdf)", () => {
                const xhr = createVerificationXHR(); // this usually takes params
                const provider = getConfigName(configId);
                const config = JSON.parse(xhr.responseText)[provider];
                const commitments = retrieveCommitments(configId, config, "hkdf");
                expect(hkdfG === commitments.G).toBeTruthy();
                expect(hkdfH === commitments.H).toBeTruthy();
            });

            test("caching commitments", () => {
                cacheCommitments(configId, "1.0", testG, testH);
                const cached10 = getCachedCommitments(configId, "1.0");
                expect(cached10.G === testG).toBeTruthy();
                expect(cached10.H === testH).toBeTruthy();
                const cached11 = getCachedCommitments(configId, "1.1");
                expect(cached11).toBeFalsy();
                setConfig(0);
                expect(getCachedCommitments(configId, "1.0")).toEqual(cached10);
            });

            test("caching commitments (hkdf)", () => {
                cacheCommitments(configId, "hkdf", hkdfG, hkdfH);
                const cachedHkdf = getCachedCommitments(configId, "hkdf");
                expect(cachedHkdf.G === hkdfG).toBeTruthy();
                expect(cachedHkdf.H === hkdfH).toBeTruthy();
                setConfig(0);
                expect(getCachedCommitments(configId, "hkdf")).toEqual(cachedHkdf);
            });

            test("error-free empty cache", () => {
                clearCachedCommitmentsMock(configId);
                expect(getCachedCommitments).not.toThrowError();
            });

            test("malformed commitments signature", () => {
                const xhr = createVerificationXHR(); // this usually takes params
                const provider = getConfigName(configId);
                const config = JSON.parse(xhr.responseText)[provider];
                expect(
                    jest.fn(() => retrieveCommitments(configId, config, "2.0-sig-bad")),
                ).toThrow("Failed on parsing commitment signature");
            });

            test("signature doesn't verify", () => {
                const xhr = createVerificationXHR(); // this usually takes params
                const provider = getConfigName(configId);
                const config = JSON.parse(xhr.responseText)[provider];
                expect(
                    jest.fn(() => retrieveCommitments(configId, config, "2.0-sig-fail")),
                ).toThrow("Invalid configuration verification");
            });

            test("expired commitments", () => {
                const xhr = createVerificationXHR(); // this usually takes params
                const provider = getConfigName(configId);
                const config = JSON.parse(xhr.responseText)[provider];
                expect(
                    jest.fn(() => retrieveCommitments(configId, config, "2.0-expired")),
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
                    setReadyIssue(configId, false);
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
                beforeEach(() => {
                    const validIds = PPConfigs().map((config) => config.id);
                    validIds.forEach((id) => {
                        if (id !== configId) {
                            setReadyIssue(id, false);
                        } else {
                            setReadyIssue(id, true);
                        }
                    });
                });

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
                    const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                    const b = beforeRequest(details, newUrl);
                    if (configId === 1) {
                        expect(b).toBeTruthy();
                        expect(b.xhr).toBeTruthy();
                        expect(b.xhr.send).toBeCalledWith(expect.stringContaining(`${captchaKey}=${EXAMPLE_RECAPTCHA_RESPONSE}`));
                        if (captchaKey == "h-captcha-response") {
                            expect(b.xhr.send).toBeCalledWith(expect.stringContaining("cf_captcha_kind=h"));
                        }
                        expect(b.xhr.send).toBeCalledWith(expect.stringContaining("blinded-tokens="));
                    } else {
                        expect(b).toBeFalsy();
                    }
                });

                test("test that true is returned with old example suffix also", () => {
                    const newUrl = new URL(EXAMPLE_HREF + OLD_EXAMPLE_SUFFIX);
                    const b = beforeRequest(details, newUrl);
                    if (configId === 1) {
                        expect(b).toBeTruthy();
                        expect(b.xhr).toBeTruthy();
                        expect(b.xhr.send).not.toBeCalledWith(expect.stringContaining(`${captchaKey}=${EXAMPLE_RECAPTCHA_RESPONSE}`));
                        if (captchaKey == "h-captcha-response") {
                            expect(b.xhr.send).not.toBeCalledWith(expect.stringContaining("cf_captcha_kind=h"));
                        }
                        expect(b.xhr.send).toBeCalledWith(expect.stringContaining("blinded-tokens="));
                    } else {
                        expect(b).toBeFalsy();
                    }
                });

                test("bad status does not sign", () => {
                    setTimeSinceLastResp(0); // reset the variables
                    const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                    workflow.__with__({XMLHttpRequest: mockXHRBadStatus})(() => {
                        const b = beforeRequest(details, newUrl);
                        if (configId === 1) {
                            expect(b).toBeTruthy();
                            expect(b.xhr).toBeTruthy();
                            const xhr = b.xhr;
                            expect(xhr.send).toBeCalledWith(expect.stringContaining(`${captchaKey}=${EXAMPLE_RECAPTCHA_RESPONSE}`));
                            if (captchaKey == "h-captcha-response") {
                                expect(xhr.send).toBeCalledWith(expect.stringContaining("cf_captcha_kind=h"));
                            }
                            expect(xhr.send).toBeCalledWith(expect.stringContaining("blinded-tokens="));
                            xhr.onreadystatechange();
                            expect(validateRespMock).not.toBeCalled();
                            expect(updateIconMock).toBeCalledTimes(1);
                            expect(updateBrowserTabMock).not.toBeCalled();
                        } else {
                            expect(b).toBeFalsy();
                        }
                    });
                });

                test("bad readyState does not sign", () => {
                    setTimeSinceLastResp(0); // reset the variables
                    const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                    workflow.__with__({XMLHttpRequest: mockXHRBadReadyState})(() => {
                        const b = beforeRequest(details, newUrl);
                        if (configId === 1) {
                            expect(b).toBeTruthy();
                            expect(b.xhr).toBeTruthy();
                            const xhr = b.xhr;
                            expect(xhr.send).toBeCalledWith(expect.stringContaining(`${captchaKey}=${EXAMPLE_RECAPTCHA_RESPONSE}`));
                            if (captchaKey == "h-captcha-response") {
                                expect(xhr.send).toBeCalledWith(expect.stringContaining("cf_captcha_kind=h"));
                            }
                            expect(xhr.send).toBeCalledWith(expect.stringContaining("blinded-tokens="));
                            xhr.onreadystatechange();
                            expect(validateRespMock).not.toBeCalled();
                            expect(updateIconMock).toBeCalledTimes(1);
                            expect(updateBrowserTabMock).not.toBeCalled();
                        } else {
                            expect(b).toBeFalsy();
                        }
                    });
                });

                test("too many tokens does not sign", () => {
                    // Always test CF here due to mock data being available
                    if (configId === 1) {
                        workflow.__with__({XMLHttpRequest: mockXHRGood})(() => {
                            function run() {
                                const b = beforeRequest(details, newUrl);
                                expect(b).toBeTruthy();
                                const xhr = b.xhr;
                                xhr.onreadystatechange();
                            }
                            setTimeSinceLastResp(0); // reset the variables
                            setMock(bypassTokensCount(configId), 400);
                            const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                            expect(run).toThrowError("upper bound");
                            expect(validateRespMock).not.toBeCalled();
                            expect(updateIconMock).toBeCalledTimes(1);
                            expect(updateBrowserTabMock).not.toBeCalled();
                        });
                    }
                });

                test("correct XHR response triggers validation", () => {
                    workflow.__with__({"validateResponse": validateRespMock, "XMLHttpRequest": mockXHRGood})(() => {
                        function run() {
                            const request = "";
                            const xhrInfo = {newUrl: newUrl, requestBody: "blinded-tokens=" + request, tokens: ""};
                            const xhr = sendXhrSignReq(xhrInfo, newUrl, configId, details.tabId);
                            xhr.responseText = "";
                            xhr.onreadystatechange();
                        }
                        setTimeSinceLastResp(0); // reset the variables
                        setMock(bypassTokensCount(configId), 0);
                        const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                        expect(run).not.toThrow();
                        expect(validateRespMock).toBeCalled();
                        expect(updateIconMock).toBeCalledTimes(1);
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
                            validateResponse(url, configId, tabId, "", "");
                        });
                    }
                    expect(run).toThrowError("invalid signature response format");
                    expect(updateIconMock).toBeCalledTimes(0);
                    expect(updateBrowserTabMock).not.toBeCalled();
                });

                test("invalid data format", () => {
                    function run() {
                        setTimeSinceLastResp(0); // reset the variables
                        const tabId = details.tabId;
                        validateResponse(url, configId, tabId, "bad-set-of-data", "");
                    }
                    expect(run).toThrowError("signature response invalid");
                    expect(updateIconMock).toBeCalledTimes(0);
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
                    let testUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                    let oldTestUrl = new URL(EXAMPLE_HREF + OLD_EXAMPLE_SUFFIX);
                    beforeEach(() => {
                        before = undefined;
                        after = undefined;
                        version = undefined;
                        testUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                        oldTestUrl = new URL(EXAMPLE_HREF + OLD_EXAMPLE_SUFFIX);
                        if (element.name.includes("hkdf")) {
                            commVersion = "hkdf";
                            if (element.name.includes("compressed")) {
                                testTokenData = testTokensHkdfCompressed;
                            } else {
                                testTokenData = testTokensHkdf;
                            }
                            G = hkdfG;
                            H = hkdfH;
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

                    function checkCache(configId, version) {
                        const cache = getCachedCommitments(configId, version);
                        if (version !== "1.0") {
                            expect(cache).toBeTruthy();
                            expect(cache.G === G).toBeTruthy();
                            expect(cache.H === H).toBeTruthy();
                        } else {
                            expect(cache).toBeFalsy();
                        }
                    }

                    function oldVersions(tokens, out) {
                        before = getMock(bypassTokensCount(1));
                        const xhr = validateAndStoreTokens(testUrl, configId, details.tabId, tokens, out);
                        expect(xhr).toBeFalsy();
                        after = getMock(bypassTokensCount(1));
                    }

                    function newVersions(tokens, out) {
                        const xhr = validateAndStoreTokens(testUrl, configId, details.tabId, tokens, out);
                        expect(xhr).toBeTruthy();
                        expect(xhr.send).toBeCalledTimes(1);
                        before = getMock(bypassTokensCount(1));
                        xhr.onreadystatechange();
                        after = getMock(bypassTokensCount(1));
                    }

                    [testUrl, oldTestUrl].forEach((url) => {
                        test(`test store tokens: ${element.name}`, () => {
                            function run() {
                                workflow.__set__("getVerificationKey", () => pubKey);
                                const tokens = [];
                                for (let i = 0; i < testTokenData.length; i++) {
                                    tokens[i] = {data: testTokenData[i].data, point: sec1DecodeFromBytes(testTokenData[i].point), blind: getBigNumFromBytes(testTokenData[i].blind)};
                                }
                                const out = parseRespString(element.string);
                                commVersion === "1.0" ? oldVersions(tokens, out) : newVersions(tokens, out);
                                version = checkVersion(configId, out.version);
                            }
                            setTimeSinceLastResp(0); // reset the variables
                            setMock(bypassTokensCount(1), 0);
                            expect(consoleMock.error).not.toBeCalled();
                            expect(run).not.toThrow();
                            expect(updateIconMock).toBeCalledTimes(2);
                            expect(updateBrowserTabMock).toBeCalledWith(details.tabId, EXAMPLE_HREF);
                            expect(after === before + testTokenData.length).toBeTruthy();
                            expect(getSpendFlagMock(testUrl.host)).toBeTruthy();
                            checkCache(configId, version);
                        });

                        test(`correct verify for cached commitments: ${element.name}`, () => {
                            cacheCommitments(configId, commVersion, G, H);
                            expect(getCachedCommitments(configId, commVersion).G === G).toBeTruthy();
                            expect(getCachedCommitments(configId, commVersion).H === H).toBeTruthy();
                            function run() {
                                workflow.__set__("getVerificationKey", () => pubKey);
                                const tokens = [];
                                for (let i = 0; i < testTokenData.length; i++) {
                                    tokens[i] = {token: testTokenData[i].data, point: sec1DecodeFromBytes(testTokenData[i].point), blind: getBigNumFromBytes(testTokenData[i].blind)};
                                }
                                const out = parseRespString(element.string);
                                before = getMock(bypassTokensCount(1));
                                const xhr = validateAndStoreTokens(url, configId, details.tabId, tokens, out);
                                expect(xhr).toBeFalsy(); // because the commitments are cached, the xhr should not be generated.
                                after = getMock(bypassTokensCount(1));
                                version = checkVersion(configId, out.version);
                            }
                            setTimeSinceLastResp(0); // reset the variables
                            setMock(bypassTokensCount(1), 0);
                            expect(consoleMock.error).not.toBeCalled();
                            expect(run).not.toThrow();
                            expect(updateIconMock).toBeCalledTimes(2);
                            expect(updateBrowserTabMock).toBeCalledWith(details.tabId, EXAMPLE_HREF);
                            expect(after === before + testTokenData.length).toBeTruthy();
                            expect(getSpendFlagMock(testUrl.host)).toBeTruthy();
                            const cache = getCachedCommitments(configId, version);
                            expect(cache.G === G).toBeTruthy();
                            expect(cache.H === H).toBeTruthy();
                        });

                        test(`correct verify when cached commitments are bad: ${element.name}`, () => {
                            // construct corrupted commitments
                            const commStruct = {};
                            commStruct[commVersion] = {L: G, H: H};
                            setMock(cachedCommitmentsKey(configId), JSON.stringify(commStruct));
                            function run() {
                                workflow.__set__("getVerificationKey", () => pubKey);
                                const tokens = [];
                                for (let i = 0; i < testTokenData.length; i++) {
                                    tokens[i] = {token: testTokenData[i].data, point: sec1DecodeFromBytes(testTokenData[i].point), blind: getBigNumFromBytes(testTokenData[i].blind)};
                                }
                                const out = parseRespString(element.string);
                                commVersion === "1.0" ? oldVersions(tokens, out) : newVersions(tokens, out);
                                version = checkVersion(configId, out.version);
                            }
                            setTimeSinceLastResp(0); // reset the variables
                            setMock(bypassTokensCount(1), 0);
                            expect(consoleMock.error).not.toBeCalled();
                            expect(run).not.toThrow();
                            commVersion === "1.0" ? expect(consoleMock.warn).not.toBeCalled() : expect(consoleMock.warn).toBeCalled();
                            expect(updateIconMock).toBeCalledTimes(2);
                            expect(updateBrowserTabMock).toBeCalledWith(details.tabId, EXAMPLE_HREF);
                            expect(after === before + testTokenData.length).toBeTruthy();
                            expect(getSpendFlagMock(testUrl.host)).toBeTruthy();
                            // bad commitments are not removed if using version 1.0
                            if (commVersion !== "1.0") {
                                checkCache(configId, version);
                            }
                        });
                    });

                    test(`test store tokens for captcha.website: ${element.name}`, () => {
                        function run() {
                            workflow.__set__("getVerificationKey", () => pubKey);
                            const tokens = [];
                            for (let i = 0; i < testTokenData.length; i++) {
                                tokens[i] = {data: testTokenData[i].data, point: sec1DecodeFromBytes(testTokenData[i].point), blind: getBigNumFromBytes(testTokenData[i].blind)};
                            }
                            const out = parseRespString(element.string);
                            commVersion === "1.0" ? oldVersions(tokens, out) : newVersions(tokens, out);
                            version = checkVersion(configId, out.version);
                        }
                        setTimeSinceLastResp(0); // reset the variables
                        setMock(bypassTokensCount(1), 0);
                        testUrl = new URL(CAPTCHA_HREF + EXAMPLE_SUFFIX);
                        expect(consoleMock.error).not.toBeCalled();
                        expect(run).not.toThrow();
                        expect(updateIconMock).toBeCalledTimes(2);
                        expect(updateBrowserTabMock).not.toBeCalled();
                        expect(after === before + testTokenData.length).toBeTruthy();
                        expect(getSpendFlagMock(testUrl.host)).toBeFalsy();
                        checkCache(configId, version);
                    });

                    test(`reloading off after sign: ${element.name}`, () => {
                        testUrl = new URL(CAPTCHA_HREF + EXAMPLE_SUFFIX);
                        function run() {
                            workflow.__set__("getVerificationKey", () => pubKey);
                            const tokens = [];
                            for (let i = 0; i < testTokenData.length; i++) {
                                tokens[i] = {data: testTokenData[i].data, point: sec1DecodeFromBytes(testTokenData[i].point), blind: getBigNumFromBytes(testTokenData[i].blind)};
                            }
                            const out = parseRespString(element.string);
                            commVersion === "1.0" ? oldVersions(tokens, out) : newVersions(tokens, out);
                            version = checkVersion(configId, out.version);
                        }
                        setTimeSinceLastResp(0); // reset the variables
                        setMock(bypassTokensCount(1), 0);
                        workflow.__with__({"reloadOnSign": () => false})(() => {
                            expect(consoleMock.error).not.toBeCalled();
                            expect(run).not.toThrow();
                            expect(updateIconMock).toBeCalledTimes(2);
                            expect(updateBrowserTabMock).not.toBeCalled();
                            expect(after === before + testTokenData.length).toBeTruthy();
                            expect(getSpendFlagMock(testUrl.host)).toBeFalsy();
                            checkCache(configId, version);
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
                            const xhr = validateAndStoreTokens(newUrl, configId, details.tabId, tokens, out);
                            xhr.onreadystatechange();
                        }
                        setTimeSinceLastResp(0); // reset the variables
                        setMock(bypassTokensCount(configId), 0);
                        const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                        expect(run).toThrow();
                        expect(updateIconMock).toBeCalledTimes(0);
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
                                const xhr = validateAndStoreTokens(newUrl, configId, details.tabId, tokens, out);
                                xhr.onreadystatechange();
                            }
                            setTimeSinceLastResp(0); // reset the variables
                            setMock(bypassTokensCount(configId), 0);
                            const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                            expect(run).toThrow();
                            expect(updateIconMock).toBeCalledTimes(0);
                            expect(updateBrowserTabMock).not.toBeCalled();
                        });

                        test("proof has bad points", () => {
                            function run() {
                                const tokens = [];
                                for (let i = 0; i < testTokens.length; i++) {
                                    tokens[i] = {data: testTokens[i].data, point: sec1DecodeFromBytes(testTokens[i].point), blind: getBigNumFromBytes(testTokens[i].blind)};
                                }
                                const out = parseRespString(respBadPoints);
                                const xhr = validateAndStoreTokens(newUrl, configId, details.tabId, tokens, out);
                                xhr.onreadystatechange();
                            }
                            setTimeSinceLastResp(0); // reset the variables
                            setMock(bypassTokensCount(configId), 0);
                            const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                            expect(run).toThrow();
                            expect(updateIconMock).toBeCalledTimes(0);
                            expect(updateBrowserTabMock).not.toBeCalled();
                        });

                        test("proof should not verify (bad lengths)", () => {
                            function run() {
                                const tokens = [];
                                for (let i = 0; i < testTokensBadLength.length; i++) {
                                    tokens[i] = {data: testTokens[i].data, point: sec1DecodeFromBytes(testTokens[i].point), blind: getBigNumFromBytes(testTokens[i].blind)};
                                }
                                const out = parseRespString(respBadProof);
                                const xhr = validateAndStoreTokens(newUrl, configId, details.tabId, tokens, out);
                                xhr.onreadystatechange();
                            }
                            setTimeSinceLastResp(0); // reset the variables
                            setMock(bypassTokensCount(configId), 0);
                            const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                            expect(run).toThrowError("Unable to verify DLEQ");
                            expect(consoleMock.error).not.toHaveBeenCalledWith(workflow.__get__("DIGEST_INEQUALITY_ERR"));
                            expect(updateIconMock).toBeCalledTimes(0);
                            expect(updateBrowserTabMock).not.toBeCalled();
                        });

                        test("proof should not verify", () => {
                            function run() {
                                const tokens = [];
                                for (let i = 0; i < testTokens.length; i++) {
                                    tokens[i] = {data: testTokens[i].data, point: sec1DecodeFromBytes(testTokens[i].point), blind: getBigNumFromBytes(testTokens[i].blind)};
                                }
                                const out = parseRespString(respBadProof);
                                const xhr = validateAndStoreTokens(newUrl, configId, details.tabId, tokens, out);
                                xhr.onreadystatechange();
                            }
                            setTimeSinceLastResp(0); // reset the variables
                            setMock(bypassTokensCount(configId), 0);
                            const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                            expect(run).toThrowError("Unable to verify DLEQ");
                            expect(consoleMock.error).toHaveBeenCalledWith(workflow.__get__("DIGEST_INEQUALITY_ERR"));
                            expect(updateIconMock).toBeCalledTimes(0);
                            expect(updateBrowserTabMock).not.toBeCalled();
                        });
                    });
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
