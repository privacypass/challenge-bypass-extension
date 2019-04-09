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
const EXAMPLE_SUFFIX = "/cdn-cgi/l/chk_captcha?id=4716480f5bb534e8&g-recaptcha-response=03AMGVjXh24S6n8-HMQadfr8AmSr-2i87s1TTWUrhfnrIcti9hw1DigphUtiZzhU5R44VlJ3CmoH1W6wZaqde7iJads2bFaErY2bok29QfgZrbhO8q6UBbwLMkVlZ803M1UyDYhA9xYJqLR4kVtKhrHkDsUEKN4vXKc3CNxQpysmvdTqdt31Lz088ptkkksGLzRluDu-Np11ER6NX8XaH2S4iwIR823r3txm4eaMoEeoLfOD5S_6WHD5RhH0B7LRa_l7Vp5ksEB-0vyHQPLQQLOYixrC_peP3dG3dnaTY5UcUAUxZK4E74glzCu2PyRpKNnQ9akFz-niWiFCY0z-cuJeOArMvGOQCC9Q";
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
    };
    url = new URL(EXAMPLE_HREF);
    setTimeSinceLastResp(Date.now());
    // Some tests make sense only for CF
    configId = configId === undefined ? 1 : configId;
    setConfig(configId); // set the active config
    workflow.__set__("issueActionUrls", () => [LISTENER_URLS]);
});

/**
 * Tests
 */
describe("commitments parsing and caching", () => {
    beforeEach(() => {
        setXHR(mockXHRCommitments, workflow);
    });

    test("parse correctly (null version)", () => {
        const xhr = createVerificationXHR(); // this usually takes params
        const commitments = retrieveCommitments(xhr);
        expect(testG === commitments.G).toBeTruthy();
        expect(testH === commitments.H).toBeTruthy();
    });

    test("parse correctly (v1.0)", () => {
        const xhr = createVerificationXHR(); // this usually takes params
        const commitments = retrieveCommitments(xhr, "1.0");
        expect(testG === commitments.G).toBeTruthy();
        expect(testH === commitments.H).toBeTruthy();
    });

    test("parse correctly (v1.1)", () => {
        const v11G = "new_11_commitment_g";
        const v11H = "new_11_commitment_h";
        const xhr = createVerificationXHR(); // this usually takes params
        const commitments = retrieveCommitments(xhr, "1.1");
        expect(v11G === commitments.G).toBeTruthy();
        expect(v11H === commitments.H).toBeTruthy();
    });

    test("parse correctly (dev)", () => {
        workflow.__with__({dev: () => true})(() => {
            const xhr = createVerificationXHR(); // this usually takes params
            const commitments = retrieveCommitments(xhr, "1.1");
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
});

each(PPConfigs().filter((config) => config.id > 0).map((config) => [config.id]))
    .describe("config_id = %i signing request is cancelled", (configId) => {
        test("signing off", () => {
            workflow.__with__({DO_SIGN: () => false})(() => {
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
            });
        });

        test("bad status does not sign", () => {
            setTimeSinceLastResp(0); // reset the variables
            const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
            workflow.__with__({"readySign": true, "XMLHttpRequest": mockXHRBadStatus})(() => {
                const b = beforeRequest(details, newUrl);
                expect(b).toBeTruthy();
                const xhr = b.xhr;
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
            beforeEach(() => {
                if (element.name === "hkdf") {
                    commVersion = "hkdf";
                    testTokenData = testTokensHkdf;
                    G = hkdfG;
                    H = hkdfH;
                } else {
                    commVersion = "1.0";
                    testTokenData = testTokens;
                    G = testG;
                    H = testH;
                }
            });
            test(`test store tokens: ${element.name}`, () => {
                let before;
                let after;
                let version;
                function run() {
                    const tokens = [];
                    for (let i=0; i<testTokenData.length; i++) {
                        tokens[i] = {data: testTokenData[i].data, point: sec1DecodePointFromBytes(testTokenData[i].point), blind: getBigNumFromBytes(testTokenData[i].blind)};
                    }
                    const out = parseRespString(element.string);
                    const xhr = validateAndStoreTokens(newUrl, details.tabId, tokens, out);
                    expect(xhr).toBeTruthy();
                    expect(xhr.send).toBeCalledTimes(1);
                    before = getMock(bypassTokensCount(1));
                    xhr.onreadystatechange();
                    after = getMock(bypassTokensCount(1));
                    version = out.version;
                }
                setTimeSinceLastResp(0); // reset the variables
                setMock(bypassTokensCount(1), 0);
                const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                expect(consoleMock.error).not.toBeCalled();
                expect(run).not.toThrow();
                expect(updateIconMock).toBeCalledTimes(3);
                expect(updateBrowserTabMock).toBeCalled();
                expect(after === before+testTokenData.length).toBeTruthy();
                expect(getSpendFlagMock(newUrl.host)).toBeTruthy();
                const cache = getCachedCommitments(version);
                expect(cache.G === G).toBeTruthy();
                expect(cache.H === H).toBeTruthy();
            });

            test(`correct verify for cached commitments: ${element.name}`, () => {
                let before;
                let after;
                let version;
                cacheCommitments(commVersion, G, H);
                expect(getCachedCommitments(commVersion).G === G).toBeTruthy();
                expect(getCachedCommitments(commVersion).H === H).toBeTruthy();
                function run() {
                    const tokens = [];
                    for (let i=0; i<testTokenData.length; i++) {
                        tokens[i] = {token: testTokenData[i].data, point: sec1DecodePointFromBytes(testTokenData[i].point), blind: getBigNumFromBytes(testTokenData[i].blind)};
                    }
                    const out = parseRespString(element.string);
                    before = getMock(bypassTokensCount(1));
                    const xhr = validateAndStoreTokens(newUrl, details.tabId, tokens, out);
                    expect(xhr).toBeFalsy(); // because the commitments are cached, the xhr should not be generated.
                    after = getMock(bypassTokensCount(1));
                    version = out.version;
                }
                setTimeSinceLastResp(0); // reset the variables
                setMock(bypassTokensCount(1), 0);
                const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                expect(consoleMock.error).not.toBeCalled();
                expect(run).not.toThrow();
                expect(updateIconMock).toBeCalledTimes(3);
                expect(updateBrowserTabMock).toBeCalled();
                expect(after === before+testTokenData.length).toBeTruthy();
                expect(getSpendFlagMock(newUrl.host)).toBeTruthy();
                const cache = getCachedCommitments(version);
                expect(cache.G === G).toBeTruthy();
                expect(cache.H === H).toBeTruthy();
            });

            test(`correct verify when cached commitments are bad: ${element.name}`, () => {
                let before;
                let after;
                let version;
                // construct corrupted commitments
                const commStruct = {};
                commStruct[commVersion] = {L: G, H: H};
                setMock(CACHED_COMMITMENTS_STRING, JSON.stringify(commStruct));
                function run() {
                    const tokens = [];
                    for (let i=0; i<testTokenData.length; i++) {
                        tokens[i] = {token: testTokenData[i].data, point: sec1DecodePointFromBytes(testTokenData[i].point), blind: getBigNumFromBytes(testTokenData[i].blind)};
                    }
                    const out = parseRespString(element.string);
                    before = getMock(bypassTokensCount(1));
                    const xhr = validateAndStoreTokens(newUrl, details.tabId, tokens, out);
                    expect(xhr).toBeTruthy();
                    expect(xhr.send).toBeCalledTimes(1);
                    before = getMock(bypassTokensCount(1));
                    xhr.onreadystatechange();
                    after = getMock(bypassTokensCount(1));
                    version = out.version;
                }
                setTimeSinceLastResp(0); // reset the variables
                setMock(bypassTokensCount(1), 0);
                const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                expect(consoleMock.error).not.toBeCalled();
                expect(run).not.toThrow();
                expect(consoleMock.warn).toBeCalled();
                expect(updateIconMock).toBeCalledTimes(3);
                expect(updateBrowserTabMock).toBeCalled();
                expect(after === before+testTokenData.length).toBeTruthy();
                expect(getSpendFlagMock(newUrl.host)).toBeTruthy();
                const cache = getCachedCommitments(version);
                expect(cache.G === G).toBeTruthy();
                expect(cache.H === H).toBeTruthy();
            });

            test(`test store tokens for captcha.website: ${element.name}`, () => {
                let before;
                let after;
                let version;
                function run() {
                    const tokens = [];
                    for (let i=0; i<testTokenData.length; i++) {
                        tokens[i] = {data: testTokenData[i].data, point: sec1DecodePointFromBytes(testTokenData[i].point), blind: getBigNumFromBytes(testTokenData[i].blind)};
                    }
                    const out = parseRespString(element.string);
                    const xhr = validateAndStoreTokens(newUrl, details.tabId, tokens, out);
                    before = getMock(bypassTokensCount(1));
                    xhr.onreadystatechange();
                    after = getMock(bypassTokensCount(1));
                    version = out.version;
                }
                setTimeSinceLastResp(0); // reset the variables
                setMock(bypassTokensCount(1), 0);
                const newUrl = new URL(CAPTCHA_HREF + EXAMPLE_SUFFIX);
                expect(consoleMock.error).not.toBeCalled();
                expect(run).not.toThrow();
                expect(updateIconMock).toBeCalledTimes(3);
                expect(updateBrowserTabMock).not.toBeCalled();
                expect(after === before+testTokenData.length).toBeTruthy();
                expect(getSpendFlagMock(newUrl.host)).toBeFalsy();
                const cache = getCachedCommitments(version);
                expect(cache.G === G).toBeTruthy();
                expect(cache.H === H).toBeTruthy();
            });

            test(`reloading off after sign: ${element.name}`, () => {
                let before;
                let after;
                const commStruct = {};
                commStruct[commVersion] = {L: G, H: H};
                const newUrl = new URL(CAPTCHA_HREF + EXAMPLE_SUFFIX);
                function run() {
                    const tokens = [];
                    for (let i=0; i<testTokenData.length; i++) {
                        tokens[i] = {data: testTokenData[i].data, point: sec1DecodePointFromBytes(testTokenData[i].point), blind: getBigNumFromBytes(testTokenData[i].blind)};
                    }
                    const out = parseRespString(element.string);
                    const xhr = validateAndStoreTokens(newUrl, details.tabId, tokens, out);
                    before = getMock(bypassTokensCount(1));
                    xhr.onreadystatechange();
                    after = getMock(bypassTokensCount(1));
                }
                setTimeSinceLastResp(0); // reset the variables
                setMock(bypassTokensCount(1), 0);
                workflow.__with__({"reloadOnSign": () => false})(() => {
                    const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                    expect(consoleMock.error).not.toBeCalled();
                    expect(run).not.toThrow();
                    expect(updateIconMock).toBeCalledTimes(3);
                    expect(updateBrowserTabMock).not.toBeCalled();
                    expect(after === before + testTokenData.length).toBeTruthy();
                    expect(getSpendFlagMock(newUrl.host)).toBeFalsy();
                });
            });
        });

        describe("test parsing errors", () => {
            test("cannot decode point", () => {
                function run() {
                    const tokens = [];
                    for (let i = 0; i < testTokens.length; i++) {
                        tokens[i] = {
                            data: testTokens[i].data,
                            point: sec1DecodePointFromBytes(testTokens[i].point),
                            blind: getBigNumFromBytes(testTokens[i].blind),
                        };
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
                            tokens[i] = {
                                data: testTokens[i].data,
                                point: sec1DecodePointFromBytes(testTokens[i].point),
                                blind: getBigNumFromBytes(testTokens[i].blind),
                            };
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
                            tokens[i] = {
                                data: testTokens[i].data,
                                point: sec1DecodePointFromBytes(testTokens[i].point),
                                blind: getBigNumFromBytes(testTokens[i].blind),
                            };
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
                            tokens[i] = {
                                data: testTokens[i].data,
                                point: sec1DecodePointFromBytes(testTokens[i].point),
                                blind: getBigNumFromBytes(testTokens[i].blind),
                            };
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
                            tokens[i] = {
                                data: testTokens[i].data,
                                point: sec1DecodePointFromBytes(testTokens[i].point),
                                blind: getBigNumFromBytes(testTokens[i].blind),
                            };
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
