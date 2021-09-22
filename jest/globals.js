/**
 * Global jest variables and functions
 *
 * @author Drazen Urch
 */

const nodeCrypto = require('crypto');

const createShake256 = require("../src/crypto/keccak/keccak");
const atob = require("atob");
const btoa = require("btoa");
const rewire = require("rewire");

let localStorageItems = new Map();
let spentUrlMock = new Map();
let spendIdMock = new Map();
let spentTabMock = new Map();
let spentHostsMock = new Map();
let futureReloadMock = new Map();
let targetMock = new Map();
let httpsRedirectMock = new Map();
let redirectCountMock = new Map();
let timeSinceLastResp = 0;
const consoleMock = {
    log: global.console.log,
    warn: jest.fn(),
    error: jest.fn(),
};

window.cryptoMock = { getRandomValues: function(x) { return nodeCrypto.randomFillSync(x); } };
window.consoleMock = consoleMock;
window.localStorageItems = localStorageItems;
window.spentUrlMock = spentUrlMock;
window.spendIdMock = spendIdMock;
window.spentTabMock = spentTabMock;
window.spentHostsMock = spentHostsMock;
window.futureReloadMock = futureReloadMock;
window.targetMock = targetMock;
window.httpsRedirectMock = httpsRedirectMock;
window.redirectCountMock = redirectCountMock;
window.timeSinceLastResp = 0;

window.workflowSet = () => {
    let workflow = rewire("../addon/test.js");

    workflow.__set__("get", getMock);
    workflow.__set__("set", setMock);

    workflow.__set__("localStorage", localStorageMock);
    workflow.__set__("localStorageItems", localStorageItems);
    workflow.__set__("updateIcon", updateIconMock);
    workflow.__set__("updateBrowserTab", updateBrowserTabMock);
    workflow.__set__("reloadBrowserTab", reloadBrowserTabMock);
    workflow.__set__("atob", atob);
    workflow.__set__("btoa", btoa);

    workflow.__set__("setSpendFlag", setSpendFlagMock);
    workflow.__set__("getSpendFlag", getSpendFlagMock);

    workflow.__set__("spentUrl", spentUrlMock);
    workflow.__set__("setSpentUrl", setSpentUrlMock);
    workflow.__set__("getSpentUrl", getSpentUrlMock);

    workflow.__set__("futureReload", futureReloadMock);
    workflow.__set__("setFutureReload", setFutureReloadMock);
    workflow.__set__("getFutureReload", getFutureReloadMock);

    workflow.__set__("httpsRedirect", httpsRedirectMock);
    workflow.__set__("setHttpsRedirect", setHttpsRedirectMock);
    workflow.__set__("getHttpsRedirect", getHttpsRedirectMock);

    workflow.__set__("redirectCount", redirectCountMock);
    workflow.__set__("setRedirectCount", setRedirectCountMock);
    workflow.__set__("getRedirectCount", getRedirectCountMock);
    workflow.__set__("incrRedirectCount", incrRedirectCountMock);

    workflow.__set__("target", targetMock);
    workflow.__set__("setTarget", setTargetMock);
    workflow.__set__("getTarget", getTargetMock);

    workflow.__set__("spendId", spendIdMock);
    workflow.__set__("setSpendId", setSpendIdMock);
    workflow.__set__("getSpendId", getSpendIdMock);

    workflow.__set__("spentTab", spentTabMock);
    workflow.__set__("pushSpentTab", pushSpentTabMock);

    workflow.__set__("spentHosts", spentHostsMock);
    workflow.__set__("setSpentHosts", setSpentHostsMock);
    workflow.__set__("getSpentHosts", getSpentHostsMock);

    workflow.__set__("shake256", () => { return createShake256(); });
    workflow.__set__("clearCachedCommitments", clearCachedCommitmentsMock);
    workflow.__set__("timeSinceLastResp", timeSinceLastResp);

    workflow.__set__("console", consoleMock);
    workflow.__set__("crypto", cryptoMock);

    const PEM = workflow.__get__("exports.PEM");
    const ASN1 = workflow.__get__("exports.ASN1");
    window.PEM = PEM;
    window.ASN1 = ASN1;
    workflow.__set__("PEM", PEM);
    workflow.__set__("ASN1", ASN1);

    const sjcl = workflow.__get__("sjcl");

    window._scalarMult = workflow.__get__("_scalarMult");
    window.sec1Encode = workflow.__get__("sec1Encode");
    window.sec1DecodeFromBytes = workflow.__get__("sec1DecodeFromBytes");
    window.sec1DecodeFromBase64 = workflow.__get__("sec1DecodeFromBase64");

    window.hkdfTestKey = sjcl.bn.fromBits(sjcl.codec.bytes.toBits([248, 78, 25, 124, 139, 113, 44, 223, 69, 45, 44, 255, 82, 222, 193, 189, 150, 34, 14, 215, 185, 166, 246, 110, 210, 140, 103, 80, 58, 230, 33, 51]));
    //  // Test points generated in a response from CF backend
    const testWorkerPoints = [
        "A3GFH/iDZMTTUuOmC9ATszHN40lp07BTyRYLhp0wnw5P",
        "Apl2KJiDa6MA24bIN+nvP2pg9g8Bx0Ac3RIHf1m1GWvX",
        "AktpxdvDKBkK70HsMAh9zIGmRF6pdPsaZlXbWOU10UJx",
        "AxMQ/h/qkdqS997iLXp9BBkV4G24HHxmOB28r2XFXEYW",
        "A3UoiqCyasKkaAfsEsNkiZ/s1cxRWBzZhTxBquwmeONs",
        "A7WoNIKaVydxIrsFFFf7OIVZcGpTgbakmJDB+6R2Sp4p",
        "A/uBvaGiL9hgkPoqUOlKe3jcx9JRGvS2OKRRayGursuy",
        "Av1jWg19Wn3pbL2vgEpEEnI9nXyilAN53dgFqol1jT0z",
        "A9w1lc9nIp/r2edLNYtwN2KJTgZAu3e/s6pU9f3OWJfd",
        "AgUyp8cbk8KF3NGwOn8Jwf15Bys6bhilmE3nS3bSC+ML"
    ];
    window.testTokensWorker = [];
    for (let i = 0; i < testWorkerPoints.length; i++) {
        const token = {};
        // random data/blind
        token.data = [237, 20, 250, 80, 161, 8, 37, 128, 78, 147, 159, 160, 227, 23, 161, 220, 22, 137, 228, 182, 45, 72, 175, 25, 57, 126, 251, 158, 253, 246, 209, 1];
        token.blind = [73, 107, 72, 26, 128, 56, 94, 59, 31, 54, 94, 206, 126, 83, 177, 12, 153, 141, 232, 123, 254, 182, 63, 221, 56, 148, 42, 62, 220, 173, 4, 134];
        token.point = sec1Encode(sec1DecodeFromBase64(testWorkerPoints[i]));
        window.testTokensWorker[i] = token;
    }

    window.LISTENER_URLS = workflow.__get__("LISTENER_URLS");

    return workflow
}

window.localStorageMock = {
    getItem: key => JSON.parse(localStorageItems[key]),
    setItem: (key, value) => localStorageItems[key] = JSON.stringify(value),
    clear: () => localStorageItems = {},
    removeItem: (key) => localStorageItems[key] = undefined,
};

window.updateIconMock = jest.fn();
window.updateBrowserTabMock = jest.fn();
window.reloadBrowserTabMock = jest.fn();
window.validateRespMock = jest.fn();

window.getMock = (key) => JSON.parse(localStorage.getItem(key));
window.setMock = (key, value) => localStorage.setItem(key, JSON.stringify(value));

window.clearCachedCommitmentsMock = (configId) => setMock(`cached-commitments-${configId}`, null);

window.setSpendFlagMock = (key, value) => setMock(key, value);
window.getSpendFlagMock = (key) => getMock(key);

window.clearLocalStorage = () => localStorage.clear();

window.bypassTokens = (config_id) => `bypass-tokens-${config_id}`;
window.bypassTokensCount = (config_id) => `bypass-tokens-count-${config_id}`;

/* mock XHR implementations */
window.mockXHR = (_xhr) => {
    _xhr.open = function(method, url) {
        _xhr.method = method;
        _xhr.url = url;
    };
    _xhr.requestHeaders = new Map();
    _xhr.getRequestHeader = function(name) {
        return _xhr.requestHeaders[name];
    }
    _xhr.setRequestHeader = function(name, value) {
        _xhr.requestHeaders[name] = value;
    }
    _xhr.overrideMimeType = jest.fn();
    _xhr.requestBody;
    _xhr.send = jest.fn();
    _xhr.onreadystatechange = function() {
    };
}

window.getSpentUrlMock = (key) => spentUrlMock[key];
window.setSpentUrlMock = (key, value) => spentUrlMock[key] = value;

window.getSpendIdMock = (key) => spendIdMock[key];
window.setSpendIdMock = (key, value) => spendIdMock[key] = value;

window.getFutureReloadMock = (key) => futureReloadMock[key];
window.setFutureReloadMock = (key, value) => futureReloadMock[key] = value;

window.getHttpsRedirectMock = (key) => httpsRedirectMock[key];
window.setHttpsRedirectMock = (key, value) => httpsRedirectMock[key] = value;

window.getRedirectCountMock = (key) => redirectCountMock[key];
window.setRedirectCountMock = (key, value) => redirectCountMock[key] = value;
window.incrRedirectCountMock = (key) => redirectCountMock[key] += 1;

window.getTargetMock = (key) => targetMock[key];
window.setTargetMock = (key, value) => targetMock[key] = value;
window.clearTargetMock = () => targetMock = new Map();

window.getSpentTabMock = (key) => spentTabMock[key];
// window.setSpentTabMock = (key, value) => spentTabMock[key] = value;
window.clearSpentTabMock = () => spentTabMock = new Map();
window.pushSpentTabMock = (key, value) => {
    if (!Array.isArray(spentTabMock[key])) {
        spentTabMock[key] = [];
    }
    spentTabMock[key].push(value);
};


window.getSpentHostsMock = (key) => spentHostsMock[key];
window.setSpentHostsMock = (key, value) => spentHostsMock[key] = value;
window.clearSpentHosts = () => spentHostsMock = new Map();

window.setXHR = (xhr, workflow) => workflow.__set__("XMLHttpRequest", xhr);

function mockXHRGood() {
    mockXHR(this);
    this.status = 200;
    this.readyState = 4;
}

window.mockXHRGood = mockXHRGood;

function mockXHRBadStatus() {
    mockXHR(this);
    this.status = 403;
    this.readyState = 4;
}

window.mockXHRBadStatus = mockXHRBadStatus;

function mockXHRBadReadyState() {
    mockXHR(this);
    this.status = 200;
    this.readyState = 5;
}

window.mockXHRBadReadyState = mockXHRBadReadyState;

function mockXHRCommitments() {
    mockXHR(this);
    this.status = 200;
    this.readyState = 4;
    this.responseText = `{
      "CF": {
        "dev": {
          "H": "${testDevH}",
          "expiry": "2022-10-07T11:42:39.843609863-07:00",
          "sig": "MEQCICfjkm06Y1aSZ9kDl2HvrqkiPRNl5XWj5P1sI8swsT5SAiBmNVicAYNcb1L0v4D1ahBGwmmAWR7SxciHHPgacg6vjg=="
        },
        "1.0": {
          "H": "${testH}",
          "expiry": "2022-10-07T11:40:51.913054052-07:00",
          "sig": "MEUCIQC8QZMf1x+EFyiTPfi5VcB8WhYHuwEdvnNt0tC3RV+ctgIgOuDoRKSYglhHGHMIyCW82IlflF8qwl1v524uWsNBxSM="
        },
        "hkdf": {
          "H": "${hkdfH}",
          "expiry": "2022-10-07T11:56:40.064212296-07:00",
          "sig": "MEUCIQD7SPey6kq5G1Pb2TnKKpIa+Yzhc2kka6jAI8JGRHnC4wIgDEWoLCqiIg1Pq3DGt2S7aW9POLYw35E0X1oXEEH1h9E="
        },
        "2.0-sig-ok": {
            "H": "${testSigH}",
            "expiry": "2022-10-02T13:44:41.894002625-07:00",
            "sig": "MEQCIC6t4Uj/RgaMpugr1DZrJnJS6GWAXvG6jjJkTZQEVbHTAiBmKE7V5lgwCOk5t/t05mUJ9yRLbw19K28t799o4yyZJA=="
        },
        "2.0-sig-bad": {
            "H": "${testSigH}",
            "expiry": "2022-10-02T13:44:41.894002625-07:00",
            "sig": "=BAD==SIGNATUREt4Uj/RgaMpugr1DZrJnJS6GWAXvG6jjJkTZQEVbHTAiBmKE7V5lgwCOk5t/t05mUJ9yRLbw19KyyZJA=="
        },
        "2.0-sig-fail": {
            "H": "${testSigH}",
            "expiry": "2022-10-02T13:44:41.894002625-07:00",
            "sig": "MEQCIC6t4Uj000000000000rJnJS6GWAXvG6jjJkTZQEVbHTAiBmKE7V5lgwCOk5t/t05mUJ9yRLbw19K28t799o4yyZJA=="
        },
        "2.0-expired": {
            "H": "${testSigH}",
            "expiry": "1900-10-02T13:44:41.894002625-07:00",
            "sig": "MEQCIC6t4Uj/RgaMpugr1DZrJnJS6GWAXvG6jjJkTZQEVbHTAiBmKE7V5lgwCOk5t/t05mUJ9yRLbw19K28t799o4yyZJA=="
        }
      }
    }`;
}

window.mockXHRCommitments = mockXHRCommitments;

function mockXHRDirectRequest() {
    mockXHR(this);
    this.status = 403;
    this.readyState = 2;
    this.HEADERS_RECEIVED = new window.XMLHttpRequest().HEADERS_RECEIVED;
    this.abort = jest.fn();
    this.responseHeaders = new Map();
    this.getResponseHeader = function(name) {
        return this.responseHeaders[name];
    };
    this.setResponseHeader = function(name, value) {
        this.responseHeaders[name] = value;
    };
};

window.mockXHRDirectRequest = mockXHRDirectRequest;

window.setTimeSinceLastResp = (value) => timeSinceLastResp = value;

window.storedTokens = `[{
    "data": [24, 62, 56, 102, 76, 127, 201, 111, 161, 218, 249, 109, 34, 122, 160, 219, 93, 186, 246, 12, 178, 249, 241, 108, 69, 181, 77, 140, 158, 13, 216, 184],
    "point": "BPzFsXoTj3RkTpcuyUUMV6eBvFkczB06iI7XNe5F65OluItpyKd0Eb9/9RFUAHiX5k7yMFVICUzCNyoRkOKUjU0=",
    "blind": "0x46af9794d53f040607a35ad297f92aef6a9879686279a12a0a478b2e0bde9089"
}, {
    "data": [131, 120, 153, 53, 158, 58, 11, 155, 160, 109, 247, 176, 176, 153, 14, 161, 150, 120, 43, 180, 188, 37, 35, 75, 52, 219, 177, 16, 24, 101, 241, 159],
    "point": "BLJ+ClrY1PkS+2hOd86eMFHYaJOFFPYmUwMEFVQJgaBgPl5bRvxN1ecSCmdX8Q7NKoWxRtbo12o2FLfN9a0HAro=",
    "blind": "0xd475b86c84c94586503f035911388dd702f056472a755e964cbbb3b58c76bd53"
}]`;
window.respBadProof = `signatures="WyJCQTBCZHlFaTdTWEYyNUdaRzVoditKMHQybXlSazJpclpPY2N0NEpFM0hsVmd0NWlnY2g0T3ltZjJ1Ky9zZENrRWtHNGIydDJVcTN2OFBwb1YvcFVheUk9IiwiQkdKWnhZWTV5c2FTUXZ6eklSOEN0Vy9BekZGdjV5QjFvdmNnems5U3ZpVlA1VzJOK2hvME9GVVl4ODI3VnhGemQ2MHlnbW9IMDAwM2dNZ3hieENuaXJFPSIsImV5SlFJam9pWlhsS1UwbHFiMmxOVkVsNlV6Rm5lbGRyV2xoTldIQTJaRVpuTUZSRmJGWmxiRkY2VmpKYWVGVkZkREpWUlVwVVZXcEdjRnBUZEhKYVJYaHpZVlpDUW1KRU1HbE1RMHBFU1dwdmFVd3laRU5aTTFaQ1ZERk9UbEZyV2toTU1XTjJZbTFXZVZSdGFFbGFibXhTVm1sMGRHVnRPRE5OTVVaR1ZWVTFSMXBzWkhkaWJteEpXWG93YVdaUlBUMGlmUT09Il0="`;
window.respBadJson = `signatures=WyJCTGZQdW9FdGxueHNic0p5dE5uUHg3Yk45N2l0KzQvd0dRVVVDWG1OM1lUcC9OOUpmMk9tWjk0TkM0WDBCbFJSTUltRUNLdUMrUlVXMm1wZlc4b1JxZG89IiwiQk5rSnBybVpVK3N1QngrWDY2Q3BEZyt4QkJlK0MzT1Z2K0U4VWhuelg0dG9ZOWgxYUo1ZUhvSmQvNHE1MjRTRUwrMHlPUjk1b2xaKzNWUVJ3ZUxqcjNzPSIsIkJOdHBFeEY4OHJTb0lwNjMvam9oMGJ0UWgyMFgwYk1TQnZMR1pCVFdKS3VzbDBZSHBzZ3FJbkNwcEpEUTJYb2xqQXV5Z250ZUh6MnR3S0lER3A2UExnND0iLCJiYWRfcHJvb2YiXQ==`;
window.testTokens = JSON.parse(`[{"data":[190,9,38,151,230,79,171,216,125,113,124,9,202,99,106,8,148,184,124,123,80,117,45,181,60,107,1,205,191,201,141,130],"point":[4,64,239,152,183,243,79,84,233,190,229,183,209,63,229,246,82,233,203,125,202,8,1,81,236,249,67,97,20,13,26,235,242,152,232,100,165,139,61,13,128,109,10,92,207,47,200,229,78,213,133,1,189,38,7,169,40,43,236,42,241,144,12,192,89],"blind":[19,68,138,141,201,18,131,37,173,223,221,188,129,173,38,241,158,120,201,16,230,98,84,221,204,124,219,84,230,201,250,121]},{"data":[180,67,45,242,171,5,79,19,220,216,252,78,168,247,113,3,211,85,214,84,225,135,188,139,247,46,249,190,202,165,163,144],"point":[4,140,140,245,238,239,73,109,226,215,43,204,10,218,230,214,46,87,129,195,242,156,84,244,149,162,208,169,168,122,35,9,143,168,62,6,102,144,190,144,188,24,39,97,226,188,82,235,36,144,148,55,185,79,2,141,115,228,234,159,51,231,204,21,100],"blind":[72,68,194,143,53,109,1,176,134,36,250,140,46,25,89,51,72,74,72,5,254,218,140,134,16,40,25,23,134,169,73,130]}]`);
window.testTokensBadLength = JSON.parse(`[{"data":[254,122,184,29,171,157,229,38,101,187,66,154,255,160,164,128,17,142,250,241,176,89,123,12,53,24,236,91,58,3,212,217],"point":[4,237,62,141,228,215,60,240,129,29,36,33,222,205,76,22,88,238,41,234,39,29,92,3,210,140,190,200,19,7,124,159,211,84,135,68,248,26,255,98,27,27,64,190,169,189,78,27,215,84,16,210,253,206,22,194,168,165,138,228,13,211,203,173,131],"blind":[44,0,207,19,25,28,76,114,193,226,49,111,160,152,161,102,207,170,195,9,31,220,120,202,182,50,135,83,7,2,134,21]}]`);
window.p256G = "BGsX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfU=";
window.testG = window.p256G;
window.testH = "BFcacpmYEBGlw8NEGb9ZMb4SOUHZD8WQdDGHV+S/iF3RRBdzb/eUFlxjsj0DlAwHYyBbpi2zJA3qu0rOLB47u08=";
window.testDevG = window.p256G;
window.testDevH = "BKjGppSCZCsL08YlF4MJcml6YkCglMvr56WlUOFjn9hOKXNa0iB9t8OHXW7lARIfYO0CZE/t1SlPA1mXdi/Rcjo=";
window.testSigG = window.p256G;
window.testSigH = "BGzqcGSPcnH5tlRj5jtVa7YLUIkkoFywO91ypKZUDQw74uVFHFNXeVpli+tmOx8SsNiKyZf7ve7neIxoYRn2lP4=";
window.hkdfG = window.p256G;
window.hkdfH = "BGEZxEbVLSG9CGoIb18ndwdbIGW6qbpXnAGMuY1qWgXBsvtZB+yvPlvEvFYoyw/m8Q8xQXwQL7xBYQ92iy+Cj6E=";
window.testTokensHkdf = JSON.parse(`[{"data":[237,20,250,80,161,8,37,128,78,147,159,160,227,23,161,220,22,137,228,182,45,72,175,25,57,126,251,158,253,246,209,1],"point":[4,96,37,164,31,129,161,96,198,72,207,232,253,202,164,46,95,125,167,167,16,85,248,226,63,29,199,228,32,74,184,75,112,80,67,186,92,112,0,18,62,31,208,88,21,10,77,55,151,0,143,87,168,178,83,119,102,217,65,156,115,150,186,82,121],"blind":[73,107,72,26,128,56,94,59,31,54,94,206,126,83,177,12,153,141,232,123,254,182,63,221,56,148,42,62,220,173,4,134]},{"data":[237,20,250,80,161,8,37,128,78,147,159,160,227,23,161,220,22,137,228,182,45,72,175,25,57,126,251,158,253,246,209,1],"point":[4,226,239,220,115,116,126,21,227,139,122,27,185,15,229,228,239,150,75,59,141,204,253,164,40,248,90,67,20,32,200,78,252,160,47,15,9,200,58,130,65,180,69,114,160,89,171,73,192,128,163,157,11,206,45,93,11,68,255,93,1,43,81,132,231],"blind":[73,107,72,26,128,56,94,59,31,54,94,206,126,83,177,12,153,141,232,123,254,182,63,221,56,148,42,62,220,173,4,134]}]`);
window.testTokensHkdfCompressed = JSON.parse(`[{"data":[237,20,250,80,161,8,37,128,78,147,159,160,227,23,161,220,22,137,228,182,45,72,175,25,57,126,251,158,253,246,209,1],"point":[3,96,37,164,31,129,161,96,198,72,207,232,253,202,164,46,95,125,167,167,16,85,248,226,63,29,199,228,32,74,184,75,112],"blind":[73,107,72,26,128,56,94,59,31,54,94,206,126,83,177,12,153,141,232,123,254,182,63,221,56,148,42,62,220,173,4,134]},{"data":[237,20,250,80,161,8,37,128,78,147,159,160,227,23,161,220,22,137,228,182,45,72,175,25,57,126,251,158,253,246,209,1],"point":[3,226,239,220,115,116,126,21,227,139,122,27,185,15,229,228,239,150,75,59,141,204,253,164,40,248,90,67,20,32,200,78,252],"blind":[73,107,72,26,128,56,94,59,31,54,94,206,126,83,177,12,153,141,232,123,254,182,63,221,56,148,42,62,220,173,4,134]}]`);
window.workersG = window.p256G;
window.workersH = "BPivZ+bqrAZzBHZtROY72/E4UGVKAanNoHL1Oteg25oTPRUkrYeVcYGfkOr425NzWOTLRfmB8cgnlUfAeN2Ikmg=";
window.testPubKey = "-----BEGIN PUBLIC KEY-----\n" +
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEthZThU2xhR0PNTsoxJ4JiydsOTGD\n" +
    "Pwy6mSLemoF0D0La+XTG06QK9UbUW7id5m8WQYjHw+A8mvoL40eaHf5Riw==\n" +
    "-----END PUBLIC KEY-----";
window.prodPubKey = "-----BEGIN PUBLIC KEY-----\n" +
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExf0AftemLr0YSz5odoj3eJv6SkOF\n" +
    "VcH7NNb2xwdEz6Pxm44tvovEl/E+si8hdIDVg1Ys+cbaWwP0jYJW3ygv+Q==\n" +
    "-----END PUBLIC KEY-----";

window.goodResponses = [
    {
        string: `signatures=WyJCQTBCZHlFaTdTWEYyNUdaRzVoditKMHQybXlSazJpclpPY2N0NEpFM0hsVmd0NWlnY2g0T3ltZjJ1Ky9zZENrRWtHNGIydDJVcTN2OFBwb1YvcFVheUk9IiwiQkdKWnhZWTV5c2FTUXZ6eklSOEN0Vy9BekZGdjV5QjFvdmNnems5U3ZpVlA1VzJOK2hvME9GVVl4ODI3VnhGemQ2MHlnbW9IMDAwM2dNZ3hieENuaXJFPSIsImV5SlFJam9pWlhsS1UwbHFiMmxhV0U1MlV6Rm5lbGRyV2xoTldIQTJaRVpuTUZSRmJGWmxiRkY2VmpKYWVGVkZkREpWUlVwVVZXcEdjRnBUZEhKYVJYaHpZVlpDUW1GNk1HbE1RMHBFU1dwdmFVd3laRU5aTTFaQ1ZERk9UbEZyV2toTU1XTjJZbTFXZVZSdGFFbGFibXhTVm1sMGRHVnRPRE5OTVVaR1ZWVTFSMXBzWkhkaWJteEpXWG93YVdaUlBUMGlmUT09Il0=`,
        name: "old",
    },
    {
        string: `signatures=eyJzaWdzIjpbIkJBMEJkeUVpN1NYRjI1R1pHNWh2K0owdDJteVJrMmlyWk9jY3Q0SkUzSGxWZ3Q1aWdjaDRPeW1mMnUrL3NkQ2tFa0c0YjJ0MlVxM3Y4UHBvVi9wVWF5ST0iLCJCR0paeFlZNXlzYVNRdnp6SVI4Q3RXL0F6RkZ2NXlCMW92Y2d6azlTdmlWUDVXMk4raG8wT0ZVWXg4MjdWeEZ6ZDYweWdtb0gwMDAzZ01neGJ4Q25pckU9Il0sInByb29mIjoiZXlKUUlqb2laWGxLVTBscWIybGFXRTUyVXpGbmVsZHJXbGhOV0hBMlpFWm5NRlJGYkZabGJGRjZWakphZUZWRmRESlZSVXBVVldwR2NGcFRkSEphUlhoellWWkNRbUY2TUdsTVEwcEVTV3B2YVV3eVpFTlpNMVpDVkRGT1RsRnJXa2hNTVdOMlltMVdlVlJ0YUVsYWJteFNWbWwwZEdWdE9ETk5NVVpHVlZVMVIxcHNaSGRpYm14SldYb3dhV1pSUFQwaWZRPT0ifQ==`,
        name: "json",
    },
    {
        string: `signatures=eyJzaWdzIjpbIkJEcTF6TGFRMkVUY3Q0Q3kyZVdSSnRZcnlGTzZBYkxET2JvY0czakFQa3RxM0ZRQzkzbjhLZlk1N2NFNEFTOE9ZWllPRjRTWE96ZjRaT1RjaXJ2R2pncz0iLCJCR1IrR3JlVWF4REJ3Y2t0MHpQaS9KNlQ2Ri9lOVpPYjh2TjJyb1dTU0ZFK0ROa1JGZVNNYUZMWTNSYzVWcTdIcUJRQncvWTZFemswaVkwWGZ5b2pmdXM9Il0sInByb29mIjoiWW1GMFkyZ3RjSEp2YjJ
        ZOWV5SlFJam9pWlhsS1JFbHFiMmxTV0VaUlZHcEpNRkZVU1hkUFIwWnlUbXBvUWxreWJIcFVSVFZPWld0YWMyVkhZelJpTTJSd1ZGaG9VMVpzVGt0Uk1FMHlUVWR3VUZsNk1HbE1RMHBUU1dwdmFWcFVSa1ZsUldneFRXMHhORk5yY0V0TlEzUkRUWHBvV2xWRWFHcFJNbFY2Vkdwc1NtSkViRWxTUkZaRllUSktlbGR0WkcxWlZtaERWMVF3YVdaUlBUMGlmUT09IiwidmVyc2lvbiI6ImhrZGYiLCJwcm5nIjoiaGtkZiJ9`,
        name: "hkdf",
    },
    {
        string: `signatures=eyJzaWdzIjpbIkF6cTF6TGFRMkVUY3Q0Q3kyZVdSSnRZcnlGTzZBYkxET2JvY0czakFQa3RxIiwiQTJSK0dyZVVheERCd2NrdDB6UGkvSjZUNkYvZTlaT2I4dk4ycm9XU1NGRSsiXSwicHJvb2YiOiJZbUYwWTJndGNISnZiMlk5ZXlKUUlqb2laWGxLUkVscWIybFVSR3d3WTJwS2ExVnRlRTFaYlRWMVZGVjRhV0ZHU2xGbFZ6QjNUVzA1VldGWE9WWlRiVkpwVjBaV2FGTXdZM1pSYTF
        aUlRUQjBWMUpVTUdsTVEwcFRTV3B2YVUxVlNuWlZWR1J6WkRCa1VtRnFSbTFVUjNSU1MzcHNNVm96YjNwVVJXUnlZbGM1YzFsdWJERmlSMVpYVGtoS1ZXVnFUbFJsYkVKSFZGUXdhV1pSUFQwaWZRPT0iLCJ2ZXJzaW9uIjoiaGtkZiIsInBybmciOiJoa2RmIn0=`,
        name: "compressed-hkdf",
    },
];
