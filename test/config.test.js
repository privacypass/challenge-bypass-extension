/**
 * Test config.js parameters for all providers
 *
 * @author: Drazen Urch
 */

import each from "jest-each";

const workflow = workflowSet();

const PPConfigs = workflow.__get__("PPConfigs");
const getConfigId = workflow.__get__("getConfigId");

let activeConfig = () => PPConfigs()[getConfigId()];

each(PPConfigs().filter((config) => config.id > 0).map((config) => [config.id]))
    .describe("CONFIG_ID = %i", (configId) => {
        beforeEach(() => {
            workflow.__set__("CONFIG_ID", configId);
        });

        test("ensure `get-more-passes-url` is a valid URL", () => {
            new URL(activeConfig()["get-more-passes-url"]);
        });

        test("ensure config `get-more-passes-url` value is correct", () => {
            const url = activeConfig()["get-more-passes-url"];
            let correctValue;
            switch (configId) {
                case 1:
                    correctValue = "https://captcha.website";
                    break;
                case 2:
                    correctValue = "https://www.hcaptcha.com/privacy-pass";
                    break;
            }
            expect(url === correctValue).toBeTruthy();
        });
    });

// For testing configuration patching
const testConfigPubKey = "-----BEGIN PUBLIC KEY-----\n" +
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4cdRphWFxgqeSpVRLbtnl66fJNvQ\n" +
"skXKm9Ww8il9LPp1rZRu2D/VJd95AZ6+1nEagVBeEnRmiOM9P++EOwVfxw==\n" +
"-----END PUBLIC KEY-----";
const cfSig = "MEUCIQCCb8mH2bEpgQtZpPHBGFbfnQ5/5JgXKQerg1cXmDu3egIgewLXTKfKl3BjPhnX4uo6Hczd/7j8FWm6fxviHZwtNaQ=";
const cfSig2 = "MEUCIDwVovXkU7wIS0az82ivhbnI//mTL3Nk3uIZsAeInFlYAiEAvrdWVOLF6fGL+VzndMX2r26pL2RwoGHkcsi59OzVFwc=";
const hcSig = "MEYCIQD7IBa36hs1GhceNxW2DSfqcKjYcdAttgBOS7/1RCuqvQIhANTwcl/UKcm5pKskfR/bDJfz2P4eAp9IIhk6rvktyQZS";
const hcSig2 = "MEUCIQDOqo6SvyhgdEcAip7l+Vl2ZYQFe5JagReNNlxjBBnCcgIgR+zJ4wqNdMJAsZeHtgyvknsr/CKdnr5bta8y4fe9fhg=";
const valid = {
    "spend-action": {
        "urls": ["https://some.example.com"],
        "header-name": "new-header",
    },
    "issue-action": {
        "urls": ["https://issue.example.com"],
        "sign-resp-format": "json",
        "tokens-per-request": 20,
        "request-identifiers": {
            "body-param": ["new-body-param"],
        },
    },
    "cookies": {
        "check-cookies": false,
        "clearance-cookie": "new_cookie_name",
    },
    "captcha-domain": "https://new.captcha.domain",
    "get-more-passes-url": "https://get.more.passes",
};
const validBadPatches = {
    "id": 4,
    "dev": true,
    "spend-action": {
        "urls": ["https://some.example.com"],
        "header-name": "new-header",
    },
    "issue-action": {
        "urls": ["https://issue.example.com"],
        "sign-resp-format": "json",
        "tokens-per-request": 20,
        "request-identifiers": {
            "body-param": ["new-body-param"],
        },
    },
    "cookies": {
        "check-cookies": false,
        "clearance-cookie": "new_cookie_name",
    },
    "captcha-domain": "https://new.captcha.domain",
    "get-more-passes-url": "https://get.more.passes",
};
const cfValid = Object.assign({}, valid);
cfValid.sig = cfSig;
const cfValidWithNonPatchables = Object.assign({}, validBadPatches);
cfValidWithNonPatchables.sig = cfSig2;
const cfInvalid = Object.assign({}, valid);
cfInvalid.sig = "BAD/SIG" + cfSig;
const hcValid = Object.assign({}, valid);
hcValid.sig = hcSig;
const hcValidWithNonPatchables = Object.assign({}, validBadPatches);
hcValidWithNonPatchables.sig = hcSig2;
const hcInvalid = Object.assign({}, valid);
hcInvalid.sig = "BAD/SIG" + hcSig;
const validConfigPatch = {
    "CF": {
        "patches": cfValid,
    },
    "HC": {
        "patches": hcValid,
    },
};
const validConfigPatchWithSomeBadPatches = {
    "CF": {
        "patches": cfValidWithNonPatchables,
    },
    "HC": {
        "patches": hcValidWithNonPatchables,
    },
};
const invalidConfigPatch = {
    "CF": {
        "patches": cfInvalid,
    },
    "HC": {
        "patches": hcInvalid,
    },
};

describe("config patches", () => {
    // const parsePublicKeyfromPEM = workflow.__get__("parsePublicKeyfromPEM");
    // const parseSignaturefromPEM = workflow.__get__("parseSignaturefromPEM");
    const getConfigForId = workflow.__get__("getConfigForId");
    const processConfigPatches = workflow.__get__("processConfigPatches");
    const CF_CONFIG_ID = workflow.__get__("CF_CONFIG_ID");
    const HC_CONFIG_ID = workflow.__get__("HC_CONFIG_ID");
    const exampleConfig = workflow.__get__("exampleConfig");
    const cfBaseConfig = workflow.__get__("cfBaseConfig");
    const hcBaseConfig = workflow.__get__("hcBaseConfig");

    // mocks the XHR for sending to the configuration repo
    function mockConfigXHRGood() {
        mockXHR(this);
        this.status = 200;
        this.readyState = 4;
        this.responseText = JSON.stringify(validConfigPatch);
    }
    function mockConfigXHRGoodButSomeBadPatches() {
        mockXHR(this);
        this.status = 200;
        this.readyState = 4;
        this.responseText = JSON.stringify(validConfigPatchWithSomeBadPatches);
    }
    function mockConfigXHRBadVerify() {
        mockXHR(this);
        this.status = 200;
        this.readyState = 4;
        this.responseText = JSON.stringify(invalidConfigPatch);
    }
    function mockConfigXHRBadResp() {
        mockXHR(this);
        this.status = 403;
        this.readyState = 4;
        this.responseText = JSON.stringify(validConfigPatch);
    }
    beforeEach(() => {
        workflow.__set__("getVerificationKey", () => testConfigPubKey);
    });

    [CF_CONFIG_ID, HC_CONFIG_ID].forEach((id) => {
        describe(`test config patches for id: ${id}`, () => {
            beforeEach(() => {
                workflow.__set__("VALID_CONFIGS", [exampleConfig(), Object.assign({}, cfBaseConfig()), Object.assign({}, hcBaseConfig())]);
            });

            test(`process config patches`, () => {
                workflow.__with__({"CONFIG_ID": id})(() => {
                    setXHR(mockConfigXHRGood, workflow);
                    const originalConfig = Object.assign({}, getConfigForId(id));
                    expect(() => {
                        const xhr = processConfigPatches(id);
                        xhr.onreadystatechange();
                    }).not.toThrow();
                    expect(consoleMock.warn).not.toHaveBeenCalled();
                    const newConfig = getConfigForId(id);
                    expect(newConfig).not.toEqual(originalConfig);
                    checkPatchesApplied(originalConfig, newConfig);
                });
            });

            test(`process config patches with some non-patched values`, () => {
                workflow.__with__({"CONFIG_ID": id})(() => {
                    setXHR(mockConfigXHRGoodButSomeBadPatches, workflow);
                    const originalConfig = Object.assign({}, getConfigForId(id));
                    expect(() => {
                        const xhr = processConfigPatches(id);
                        xhr.onreadystatechange();
                    }).not.toThrow();
                    expect(consoleMock.warn).not.toHaveBeenCalledWith("[privacy-pass]: Not processing config as unable to verify signature on patches");
                    const newConfig = getConfigForId(id);
                    expect(newConfig).not.toEqual(originalConfig);
                    checkPatchesApplied(originalConfig, newConfig);
                    expect(newConfig["id"]).toEqual(originalConfig["id"]);
                    expect(newConfig["dev"]).toEqual(originalConfig["dev"]);
                });
            });

            test(`do not process config patches for bad sig`, () => {
                workflow.__with__({"CONFIG_ID": id})(() => {
                    setXHR(mockConfigXHRBadVerify, workflow);
                    const originalConfig = Object.assign({}, getConfigForId(id));
                    expect(() => {
                        const xhr = processConfigPatches(id);
                        xhr.onreadystatechange();
                    }).not.toThrow();
                    expect(consoleMock.warn).toHaveBeenCalledWith("[privacy-pass]: Not processing config as unable to verify signature on patches");
                    const newConfig = getConfigForId(id);
                    expect(newConfig).toEqual(originalConfig);
                });
            });

            test(`do not process config patches for bad resp`, () => {
                workflow.__with__({"CONFIG_ID": id})(() => {
                    setXHR(mockConfigXHRBadResp, workflow);
                    const originalConfig = Object.assign({}, getConfigForId(id));
                    expect(() => {
                        const xhr = processConfigPatches(id);
                        xhr.onreadystatechange();
                    }).not.toThrow();
                    const newConfig = getConfigForId(id);
                    expect(newConfig).toEqual(originalConfig);
                });
            });
        });
    });
});

function checkPatchesApplied(originalConfig, newConfig) {
    // check that patched values are correct
    expect(newConfig["spend-action"]["urls"]).toEqual(valid["spend-action"]["urls"]);
    expect(newConfig["spend-action"]["header-name"]).toEqual(valid["spend-action"]["header-name"]);
    expect(newConfig["issue-action"]["urls"]).toEqual(valid["issue-action"]["urls"]);
    expect(newConfig["issue-action"]["sign-resp-format"]).toEqual(valid["issue-action"]["sign-resp-format"]);
    expect(newConfig["issue-action"]["tokens-per-request"]).toEqual(valid["issue-action"]["tokens-per-request"]);
    expect(newConfig["issue-action"]["request-identifiers"]["body-param"]).toEqual(valid["issue-action"]["request-identifiers"]["body-param"]);
    expect(newConfig["cookies"]["check-cookies"]).toEqual(valid["cookies"]["check-cookies"]);
    expect(newConfig["cookies"]["clearance_cookie"]).toEqual(valid["cookies"]["clearance_cookie"]);
    expect(newConfig["captcha-domain"]).toEqual(valid["captcha-domain"]);
    expect(newConfig["get-more-passes-url"]).toEqual(valid["get-more-passes-url"]);

    // check that unpatches values are maintained
    expect(newConfig["opt-endpoints"]).toEqual(originalConfig["opt-endpoints"]);
    expect(newConfig["issue-action"]["request-identifiers"]["query-param"]).toEqual(originalConfig["issue-action"]["request-identifiers"]["query-param"]);
    expect(newConfig["issue-action"]["request-identifiers"]["post-processed"]).toEqual(originalConfig["issue-action"]["request-identifiers"]["post-processed"]);
    expect(newConfig["opt-endpoints"]).toEqual(originalConfig["opt-endpoints"]);
    expect(newConfig["send-h2c-params"]).toEqual(originalConfig["send-h2c-params"]);
    expect(newConfig["spend-action"]["header-host-name"]).toEqual(originalConfig["spend-action"]["header-host-name"]);
    expect(newConfig["spend-action"]["header-path-name"]).toEqual(originalConfig["spend-action"]["header-path-name"]);
}
