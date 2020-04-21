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
const MOCK_EXT_VERSION = "2.0.5"; // fixed version for testing
workflow.__set__("extVersion", () => MOCK_EXT_VERSION);
const extVersionAsArray = workflow.__get__("extVersionAsArray");
const testConfigPubKey = "-----BEGIN PUBLIC KEY-----\n" +
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4cdRphWFxgqeSpVRLbtnl66fJNvQ\n" +
"skXKm9Ww8il9LPp1rZRu2D/VJd95AZ6+1nEagVBeEnRmiOM9P++EOwVfxw==\n" +
"-----END PUBLIC KEY-----";
const sig10 = "MEUCIQCJKxh/Ik5jrs47VYBby4OZyXxLxgOhnAkyTmnB//jbiAIgODqfuqjwTrXiRorkdluPpxmYQV2Dz5dXDOXMf3GVzCI=";
const sig11 = "MEUCIEB5r7N+DKA9vwACSa/HISyWuXUKghGACNxu6a2WTwCFAiEAwFjngF7Z2GEhESBu3pR7J9aEOi1toPJz50/oPDRZWjs=";
const sig20 = "MEYCIQChW7U+1thCKm3akMkz8903q/4K7gdMIBe95Ev0zrZbDQIhALJZG412wRCrIq4/v8kqDPbAOVeVSSA3p6GQDlwomtvO";
const sig21 = "MEYCIQDjtv0krYeMO870kjj8aCfGWfe2lUycW8LBxXHZZf6c0gIhALN/KuwR1FCKDAnFq8pKZHDCgpQvaXh4CdRNaEDLTrHo";
const valid = [
    {
        "min-version": "2.0.0",
        "config": {
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
        },
        "sig": sig10,
    },
    {
        "min-version": "2.0.0",
        "config": {
            "cookies": {
                "check-cookies": false,
                "clearance-cookie": "new_cookie_name",
            },
            "captcha-domain": "https://new.captcha.domain",
            "get-more-passes-url": "https://get.more.passes",
        },
        "sig": sig11,
    },
];
const arr = extVersionAsArray();
arr[2] = arr[2]++;
const validBadVersion = [
    {
        "min-version": "2.0.0",
        "config": {
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
        },
        "sig": sig10,
    },
    {
        "min-version": `${arr[0]}.${arr[1]}.${arr[2]}`,
        "config": {
            "cookies": {
                "check-cookies": false,
                "clearance-cookie": "new_cookie_name",
            },
            "captcha-domain": "https://new.captcha.domain",
            "get-more-passes-url": "https://get.more.passes",
        },
        "sig": sig11,
    },
];
const validBadPatches = [
    {
        "min-version": "2.0.0",
        "config": {
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
        },
        "sig": sig20,
    },
    {
        "min-version": "2.0.0",
        "config": {
            "id": 4,
            "cookies": {
                "check-cookies": false,
                "clearance-cookie": "new_cookie_name",
            },
            "captcha-domain": "https://new.captcha.domain",
            "get-more-passes-url": "https://get.more.passes",
        },
        "sig": sig21,
    },
];
const invalid0 = Object.assign({}, valid[0]);
invalid0.sig = "BAD/SIG" + sig10;
const invalid1 = Object.assign({}, valid[1]);
invalid1.sig = "BAD/SIG" + sig11;
const invalid = [valid[0], invalid1];
const validConfigPatch = {
    "CF": {
        "patches": valid,
    },
    "HC": {
        "patches": valid,
    },
};
const validConfigPatchBadPatches = {
    "CF": {
        "patches": validBadPatches,
    },
    "HC": {
        "patches": validBadPatches,
    },
};
const validConfigPatchBadVersion = {
    "CF": {
        "patches": validBadVersion,
    },
    "HC": {
        "patches": validBadVersion,
    },
};
const invalidConfigPatch = {
    "CF": {
        "patches": invalid,
    },
    "HC": {
        "patches": invalid,
    },
};
const invalidFormatPatch = {
    "CF": {
        "patches": Object.assign({}, valid[0]),
    },
    "HC": {
        "patches": Object.assign({}, valid[0]),
    },
};

describe("config patches version tests", () => {
    const applicablePatch = workflow.__get__("applicablePatch");
    const extVersion = extVersionAsArray();
    beforeEach(() => {
        // have to reset version as we change it in some of the tests
        workflow.__set__("extVersion", () => MOCK_EXT_VERSION);
    });

    test("good version", () => {
        expect(applicablePatch("2.0.0")).toBeTruthy();
    });

    test("good version, exact", () => {
        expect(applicablePatch("2.0.5")).toBeTruthy();
    });

    test("good version, patch version length = 4", () => {
        expect(applicablePatch("2.0.0.1")).toBeTruthy();
    });

    test("good version, ext version length = 4", () => {
        workflow.__set__("extVersion", () => "2.0.5.1");
        expect(applicablePatch("2.0.0")).toBeTruthy();
    });

    test("good version, both lengths = 4", () => {
        workflow.__set__("extVersion", () => "2.0.5.1");
        expect(applicablePatch("2.0.5.1")).toBeTruthy();
    });

    test("bad version (0)", () => {
        const arr = Object.assign([], extVersion);
        arr[0] = arr[0]++;
        expect(applicablePatch(arr)).toBeFalsy();
    });

    test("bad version (1)", () => {
        const arr = Object.assign([], extVersion);
        arr[1] = arr[1]++;
        expect(applicablePatch(arr)).toBeFalsy();
    });

    test("bad version (2)", () => {
        const arr = Object.assign([], extVersion);
        arr[2] = arr[2]++;
        expect(applicablePatch(arr)).toBeFalsy();
    });

    test("bad version (3)", () => {
        workflow.__set__("extVersion", () => "2.0.5.1");
        expect(applicablePatch("2.0.5.2")).toBeFalsy();
    });
});

describe("config patches integration test", () => {
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
    function mockConfigXHRGoodBadPatches() {
        mockXHR(this);
        this.status = 200;
        this.readyState = 4;
        this.responseText = JSON.stringify(validConfigPatchBadPatches);
    }
    function mockConfigXHRGoodBadVersion() {
        mockXHR(this);
        this.status = 200;
        this.readyState = 4;
        this.responseText = JSON.stringify(validConfigPatchBadVersion);
    }
    function mockConfigXHRBadVerify() {
        mockXHR(this);
        this.status = 200;
        this.readyState = 4;
        this.responseText = JSON.stringify(invalidConfigPatch);
    }
    function mockConfigXHRBadFormat() {
        mockXHR(this);
        this.status = 200;
        this.readyState = 4;
        this.responseText = JSON.stringify(invalidFormatPatch);
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
                    setXHR(mockConfigXHRGoodBadPatches, workflow);
                    const originalConfig = Object.assign({}, getConfigForId(id));
                    expect(() => {
                        const xhr = processConfigPatches(id);
                        xhr.onreadystatechange();
                    }).not.toThrow();
                    expect(consoleMock.warn).not.toHaveBeenCalledWith("[privacy-pass]: Not processing patch as unable to verify signature");
                    const newConfig = getConfigForId(id);
                    expect(newConfig).not.toEqual(originalConfig);
                    checkPatchesApplied(originalConfig, newConfig);
                    expect(newConfig["id"]).toEqual(originalConfig["id"]);
                    expect(newConfig["dev"]).toEqual(originalConfig["dev"]);
                });
            });

            test(`do not process config patches for bad versions`, () => {
                workflow.__with__({"CONFIG_ID": id})(() => {
                    setXHR(mockConfigXHRGoodBadVersion, workflow);
                    const originalConfig = Object.assign({}, getConfigForId(id));
                    expect(() => {
                        const xhr = processConfigPatches(id);
                        xhr.onreadystatechange();
                    }).not.toThrow();
                    expect(consoleMock.warn).toHaveBeenCalledWith("[privacy-pass]: Not processing patch as unable to verify signature");
                    const newConfig = getConfigForId(id);
                    checkInvalidPatchesNotApplied(originalConfig, newConfig);
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
                    expect(consoleMock.warn).toHaveBeenCalledWith("[privacy-pass]: Not processing patch as unable to verify signature");
                    const newConfig = getConfigForId(id);
                    checkInvalidPatchesNotApplied(originalConfig, newConfig);
                });
            });

            test(`do not process config patches for bad formats`, () => {
                workflow.__with__({"CONFIG_ID": id})(() => {
                    setXHR(mockConfigXHRBadFormat, workflow);
                    const originalConfig = Object.assign({}, getConfigForId(id));
                    expect(() => {
                        const xhr = processConfigPatches(id);
                        xhr.onreadystatechange();
                    }).not.toThrow();
                    expect(consoleMock.warn).toHaveBeenCalledWith("[privacy-pass]: Patches not specified in correct format");
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
    // check that alll patched values are correct
    expect(newConfig["spend-action"]["urls"]).toEqual(valid[0]["config"]["spend-action"]["urls"]);
    expect(newConfig["spend-action"]["header-name"]).toEqual(valid[0]["config"]["spend-action"]["header-name"]);
    expect(newConfig["issue-action"]["urls"]).toEqual(valid[0]["config"]["issue-action"]["urls"]);
    expect(newConfig["issue-action"]["sign-resp-format"]).toEqual(valid[0]["config"]["issue-action"]["sign-resp-format"]);
    expect(newConfig["issue-action"]["tokens-per-request"]).toEqual(valid[0]["config"]["issue-action"]["tokens-per-request"]);
    expect(newConfig["issue-action"]["request-identifiers"]["body-param"]).toEqual(valid[0]["config"]["issue-action"]["request-identifiers"]["body-param"]);
    expect(newConfig["cookies"]["check-cookies"]).toEqual(valid[1]["config"]["cookies"]["check-cookies"]);
    expect(newConfig["cookies"]["clearance-cookie"]).toEqual(valid[1]["config"]["cookies"]["clearance-cookie"]);
    expect(newConfig["captcha-domain"]).toEqual(valid[1]["config"]["captcha-domain"]);
    expect(newConfig["get-more-passes-url"]).toEqual(valid[1]["config"]["get-more-passes-url"]);

    checkNonPatchedValues(originalConfig, newConfig);
}

function checkInvalidPatchesNotApplied(originalConfig, newConfig) {
    expect(newConfig["spend-action"]["urls"]).toEqual(valid[0]["config"]["spend-action"]["urls"]);
    expect(newConfig["spend-action"]["header-name"]).toEqual(valid[0]["config"]["spend-action"]["header-name"]);
    expect(newConfig["issue-action"]["urls"]).toEqual(valid[0]["config"]["issue-action"]["urls"]);
    expect(newConfig["issue-action"]["sign-resp-format"]).toEqual(valid[0]["config"]["issue-action"]["sign-resp-format"]);
    expect(newConfig["issue-action"]["tokens-per-request"]).toEqual(valid[0]["config"]["issue-action"]["tokens-per-request"]);
    expect(newConfig["issue-action"]["request-identifiers"]["body-param"]).toEqual(valid[0]["config"]["issue-action"]["request-identifiers"]["body-param"]);

    // this patch is invalid so nothing should have changed
    expect(newConfig["cookies"]["check-cookies"]).not.toEqual(valid[1]["config"]["cookies"]["check-cookies"]);
    expect(newConfig["cookies"]["clearance-cookie"]).not.toEqual(valid[1]["config"]["cookies"]["clearance-cookie"]);
    expect(newConfig["captcha-domain"]).not.toEqual(valid[1]["config"]["captcha-domain"]);
    expect(newConfig["get-more-passes-url"]).not.toEqual(valid[1]["config"]["get-more-passes-url"]);

    checkNonPatchedValues(originalConfig, newConfig);
}

// check that unpatched values are maintained
function checkNonPatchedValues(originalConfig, newConfig) {
    expect(newConfig["opt-endpoints"]).toEqual(originalConfig["opt-endpoints"]);
    expect(newConfig["issue-action"]["request-identifiers"]["query-param"]).toEqual(originalConfig["issue-action"]["request-identifiers"]["query-param"]);
    expect(newConfig["issue-action"]["request-identifiers"]["post-processed"]).toEqual(originalConfig["issue-action"]["request-identifiers"]["post-processed"]);
    expect(newConfig["send-h2c-params"]).toEqual(originalConfig["send-h2c-params"]);
    expect(newConfig["spend-action"]["header-host-name"]).toEqual(originalConfig["spend-action"]["header-host-name"]);
    expect(newConfig["spend-action"]["header-path-name"]).toEqual(originalConfig["spend-action"]["header-path-name"]);
}
