/**
 * Global jest variables and functions
 *
 * @author Drazen Urch
 */


import atob from "atob";
import btoa from "btoa";
import createShake256 from "../src/crypto/keccak/keccak";
import rewire from "rewire";

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
    warn: jest.fn(),
    error: jest.fn(),
};

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

    workflow.__set__("shake256", () => {return createShake256();});
    workflow.__set__("clearCachedCommitments", clearCachedCommitmentsMock);
    workflow.__set__("timeSinceLastResp", timeSinceLastResp);

    workflow.__set__("console", consoleMock);

    const sjcl = workflow.__get__("sjcl");

    window._scalarMult = workflow.__get__("_scalarMult");
    window.sec1Encode = workflow.__get__("sec1Encode");
    window.sec1DecodeFromBytes = workflow.__get__("sec1DecodeFromBytes");

    window.hkdfTestKey = sjcl.bn.fromBits(sjcl.codec.bytes.toBits([248, 78, 25, 124, 139, 113, 44, 223, 69, 45, 44, 255, 82, 222, 193, 189, 150, 34, 14, 215, 185, 166, 246, 110, 210, 140, 103, 80, 58, 230, 33, 51]));
    window.hkdfG = sjcl.codec.base64.fromBits(sjcl.codec.bytes.toBits(genBytes));
    window.hkdfH = sjcl.codec.base64.fromBits(sjcl.codec.bytes.toBits(hBytes));

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

window.CACHED_COMMITMENTS_STRING = "cached-commitments";
window.clearCachedCommitmentsMock = () => setMock(CACHED_COMMITMENTS_STRING, null);

window.setSpendFlagMock = (key, value) => setMock(key, value);
window.getSpendFlagMock = (key) => getMock(key);

window.clearLocalStorage = () => localStorage.clear();

window.bypassTokens = (config_id) => `bypass-tokens-${config_id}`;
window.bypassTokensCount = (config_id) => `bypass-tokens-count-${config_id}`;

/* mock XHR implementations */
window.mockXHR = (_xhr) => {
    _xhr.open = function (method, url) {
        _xhr.method = method;
        _xhr.url = url;
    };
    _xhr.requestHeaders = new Map();
    _xhr.getRequestHeader = function (name) {
        return _xhr.requestHeaders[name];
    }
    _xhr.setRequestHeader = function (name, value) {
        _xhr.requestHeaders[name] = value;
    }
    _xhr.overrideMimeType = jest.fn();
    _xhr.body;
    _xhr.send = jest.fn();
    _xhr.onreadystatechange = function () {
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
          "G": "${testDevG}",
          "H": "${testDevH}"
        },
        "1.0": {
          "G": "${testG}",
          "H": "${testH}"
        },
        "1.1": {
          "G": "new_11_commitment_g",
          "H": "new_11_commitment_h"
        },
        "hkdf": {
          "G": "${hkdfG}",
          "H": "${hkdfH}"
        },
        "1.01": {
            "H": "${testSigH}",
            "expiry": "2019-12-20T05:07:00.298053015-08:00",
            "sig": "MEQCIDFSb4PqkVAn5wdAyklVMvo5CE2SyAv0redzHnNo68ZnAiBbPcKMCctPHBrTatNMw8xYbesMT8EFTBCwRXAP7QlOsw=="
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
window.respBadProof = `signatures=WyJCQVRkL01qTnNuTTZxaHBQZzFLS216RnVHOUNQRzdFbERVSU5EVjFJQmd5WTN2RkVrdENUMk8ybW82dGNNLy9qMWE2Zkoyb1dMb2Z5MGZqYWVjTlBEeWM9IiwiQk9aQnY4dnNxdFg3VzRKcFlSZERHMm5QSEtHTDBMVUtFY1VCY1ZTZjcrcnlxRHRRdC9WZFFlZHRLMkVNa1AvMXZvcjl6dkkvRDZ0ekNZQi9CQkRLRkpRPSIsIkJNMW9UdW9Bc3RiTzQvN3ZIcUEwaDhNbG5rNG5UdEJ6NzdvN25RWitqM2RhQ09FU3RXM1VTWHRKdGdmcnVramZBNkxDUksyUmpFVGZVUWU1cmhpaEY0ND0iLCJZbUYwWTJndGNISnZiMlk5ZXlKRElqcGJJbXhrWldacVJ6QXZaRXh2VUhVdkt6UjNURkl5TTJaM2JsWllWVGQwY1dSYU5uSmhlbWhqYTNSa1JYYzlJaXdpZWt4M2QyZHROVGxaU0c5T2FtRkVhVkJ5UzBSd1VrOU5ZMnBsTlhwc2IxaEtXa2MyY1ZJMGJUQXhRVDBpTENKbl
IzTnBTRE5XYkRGRVMwVjFaMjl1VVRoRmVFODVaRkkxU0Voc05HUTBNMmRGUWpWd04wUkRhV3BSUFNKZExDSk5JanBiSWtKSU5VSndZVkpUZEdwWkwwMXNNMVVyUW5aREwzUjNaRzVpVldzMVdFZG9Nbk5rZUZOV09HWkJkR2cyWXpKaFlreHhZV1o2Y2pKcEsySm5kVTVpS3l0Mk0xaEVOV3RHTWt0V2JFaGtSamxzYTNwNmRtVTVhejBpTENKQ1RIWTFZM2hwVlZscVRWbEdiMHczY1VGWmVTO
TBiSGRsUmtGeGRrWlBiVEZQWVZFeFVIVnJaRUZYWTB0NFpqZEpaekZWU0VoR05saENOMWxuVVd0dVFrOTVkSHBwYTNsUGFFZHpUbmcyYjFoMFZHbGFVRms5SWl3aVFsQTVLMkZUWlZKbU9XbDZNRGsyWm5Gb1NreHNTMFIwYjFORVRTdDFVVUpOVVVobGJHVktia1prZUdzMWRURnViRlF2VDFrNVZsaEdSM0JvYWxWSGJGSkllRW92UTJoaVZrdDNSVGwxZG1KSmJYWnhjWGxSUFNKZExDSlFJ
am9pWlhsS1NFbHFiMmxSYXpsd1drVldNVlI2YkVsVk1IQjZWRlp3V2xKVE9WRmFiVTB4VWtOemQxSlZlSFZOUjBwNFlVZHdSbHBYV1hsVWVrSXhTekIwUW1SNlRtMVZSVEZKVTBab01GWnRlRVpSYmxwYVlXdFZNVk5UT1ZCVWJWazFWVE5zVlZKc1RuSlRSRTUwVkVVMVNXRXhUWGRPYTFJeFRtMW9VbEJUU1hOSmF6QnBUMmxLUTFGV1drOWlhMmhQWTI1c1NWcFlRbnBPUmtKNlZsZFdTMUp
xYTNkWlZGSldWbXhyZWxkclVqTlNWa0pRV2tWck5WRnROV3hoZW1oRVUwYzVXRkp0VlhaWGJUbFNUMWRrY0ZadFJuSlVSa0o1VjBoQmVVNUdRbEZqUlVwSVVXeGtiV0pGV25aVE1IQnFWa2RrVTFWdFJYSk5SVlU1U1dsM2FWTkRTVFpKYTBwSlZERkNUMUZXWkZsVmJXc3dZMms1VDFKWVFqQlVNbXhOVkROQk5GUldUak5aTVdkM1pHdG9lVlpyVWxOWFNGbDRUbXR3ZFdJelpHcE5WMVpaVj
BjNE1XVkZXa2RUTUd4UVUxUmFkRlpZUVRSaGVtdDJXbGRPYUU1V1dscE5SR1JyVVcxb1FscFVhRkphYkVsMlVteE9VMWRVTUdsTVEwcGhTV3B2YVZGclJrbE9SMVY2WlZkU05WRlhXbXBVYm1jMVlYcGplVlJJU2tKaVJ6bGFWREJHYVdGc1RsQlNSM2Q0V2pGU1ZHRnFXbXRqTVVGNVN6TkNOVkpZVWxGWFJHd3pWWHBPU1ZSNlVrNU5iazVNWkZkT01GTXdSazFUTW14MllVaHdlRTR5V1RGa
mFrcFhVekJKTUU5SVJraE5SR3hXVUZOSmMwbHNTV2xQYVVwTVlVWk9WMVpYY0V0aVZHaFlZMFJDTUU5RVRuRk9NRlpTV1hwa00xSkZhekZYYkU1NFRWUkNVRTlIWkROVlJHYzBaRE5XVTFwWVFuSlFVMGx6U1d0TmFVOXBTa2xXUjFaTFZWVTVOVkZVVWxaV2F6RlRVbFJXVmxkRldqWlhiRWt5Wkd4d1RsSkZkSHBsYVhSelYwVXhkMk5IZERGYVJGWlBVbGhPVGxCVFNqa2lMQ0phSWpwYklr
SkJTemhFUVU1bU9HRldjSEZtVVZoS1J5dFZkQzlJWVZOeU5XWmpaVnB1WlVkbmNFMXRaR0ZLUTNNeVUya3dVbWRaVm5sNWNERlVUU3RwTTBaa01VRkhWMmgyYVdKNFRYcG9SbVY1WTFOc0swSXZkMmR2YXowaUxDSkNSMWc0YjFFeVpGRkpjV1ZLZEZwMGNtOWthM1E1YlhKdFJtaEJiVWRWVUZsbGVWVTNVRGRqWlRsVWRURm9LM0F3Vm1oTFZXbFpVek13WkVRclVua3JjVVZSYm05VE5FSjZ
jRmhpUmxoUFkzQnhhM0JIVjJjOUlpd2lRa2RzUWpWak4yaFBaWE5GZEU5U2VYRldiREZHVFRkR1ozcHZNR3QzVlhwQ2FYRnNhVkZSVEVScVN6TnhiRGw0UWxaaFJrZHRhREIwVVdSYWNsTnJXR3A0VTB4dWVVZHNiRk5wT0ZwWVJYazROMjFOVDBGRlBTSmRmUT09Il0=`;
window.respBadJson = `signatures=WyJCTGZQdW9FdGxueHNic0p5dE5uUHg3Yk45N2l0KzQvd0dRVVVDWG1OM1lUcC9OOUpmMk9tWjk0TkM0WDBCbFJSTUltRUNLdUMrUlVXMm1wZlc4b1JxZG89IiwiQk5rSnBybVpVK3N1QngrWDY2Q3BEZyt4QkJlK0MzT1Z2K0U4VWhuelg0dG9ZOWgxYUo1ZUhvSmQvNHE1MjRTRUwrMHlPUjk1b2xaKzNWUVJ3ZUxqcjNzPSIsIkJOdHBFeEY4OHJTb0lwNjMvam9oMGJ0UWgyMFgwYk1TQnZMR1pCVFdKS3VzbDBZSHBzZ3FJbkNwcEpEUTJYb2xqQXV5Z250ZUh6MnR3S0lER3A2UExnND0iLCJiYWRfcHJvb2YiXQ==`;
window.testTokens = JSON.parse(`[{"data":[237,20,250,80,161,8,37,128,78,147,159,160,227,23,161,220,22,137,228,182,45,72,175,25,57,126,251,158,253,246,209,1],"point":[4,178,119,34,84,93,23,7,255,30,232,166,5,142,110,153,178,32,198,114,30,102,86,121,195,92,214,144,84,155,61,235,94,227,235,75,30,198,92,206,234,196,86,106,0,79,14,9,225,63,249,58,139,100,21,117,195,204,225,53,217,141,220,224,35],"blind":[73,107,72,26,128,56,94,59,31,54,94,206,126,83,177,12,153,141,232,123,254,182,63,221,56,148,42,62,220,173,4,134]},{"data":[254,122,184,29,171,157,229,38,101,187,66,154,255,160,164,128,17,142,250,241,176,89,123,12,53,24,236,91,58,3,212,217],"point":[4,237,62,141,228,215,60,240,129,29,36,33,222,205,76,22,88,238,41,234,39,29,92,3,210,140,190,200,19,7,124,159,211,84,135,68,248,26,255,98,27,27,64,190,169,189,78,27,215,84,16,210,253,206,22,194,168,165,138,228,13,211,203,173,131],"blind":[44,0,207,19,25,28,76,114,193,226,49,111,160,152,161,102,207,170,195,9,31,220,120,202,182,50,135,83,7,2,134,21]},{"data":[223,42,23,79,237,61,125,106,86,135,234,109,171,67,86,202,166,142,77,238,69,175,78,67,214,214,246,171,20,178,166,251],"point":[4,1,217,22,212,2,213,172,249,228,15,57,187,210,224,69,225,254,67,195,37,79,189,197,43,1,57,213,66,100,118,118,239,41,145,71,177,212,83,25,55,198,198,40,110,29,155,189,82,17,11,156,4,99,60,168,157,182,156,187,166,71,251,176,191],"blind":[74,150,233,91,28,35,116,26,6,87,77,9,8,200,166,69,152,61,192,210,236,207,68,138,250,104,16,195,92,232,43,132]}]`);
window.testTokensBadLength = JSON.parse(`[{"data":[254,122,184,29,171,157,229,38,101,187,66,154,255,160,164,128,17,142,250,241,176,89,123,12,53,24,236,91,58,3,212,217],"point":[4,237,62,141,228,215,60,240,129,29,36,33,222,205,76,22,88,238,41,234,39,29,92,3,210,140,190,200,19,7,124,159,211,84,135,68,248,26,255,98,27,27,64,190,169,189,78,27,215,84,16,210,253,206,22,194,168,165,138,228,13,211,203,173,131],"blind":[44,0,207,19,25,28,76,114,193,226,49,111,160,152,161,102,207,170,195,9,31,220,120,202,182,50,135,83,7,2,134,21]},{"data":[223,42,23,79,237,61,125,106,86,135,234,109,171,67,86,202,166,142,77,238,69,175,78,67,214,214,246,171,20,178,166,251],"point":[4,1,217,22,212,2,213,172,249,228,15,57,187,210,224,69,225,254,67,195,37,79,189,197,43,1,57,213,66,100,118,118,239,41,145,71,177,212,83,25,55,198,198,40,110,29,155,189,82,17,11,156,4,99,60,168,157,182,156,187,166,71,251,176,191],"blind":[74,150,233,91,28,35,116,26,6,87,77,9,8,200,166,69,152,61,192,210,236,207,68,138,250,104,16,195,92,232,43,132]}]`);
window.testG = "BOidEuO9HSJsMZYE/Pfc5D+0ELn0bqhjEef2O0u+KAw3fPMHHXtVlEBvYjE5I/ONf9SyTFSkH3mLNHkS06Du6hQ=";
window.testH = "BHOPNAWXRi4r/NEptOiLOp8MSwcX0vHrVDRXv16Jnowc1eXXo5xFFKIOI6mUp8k9/eca5VY07dBhAe8QfR/FSRY=";
window.testDevG = "BIpWWWWFtDRODAHEzZlvjKyDwQAdh72mYKMAsGrtwsG7XmMxsy89gfiOFbX3RZ9Ik6jEYWyJB0TmnWNVeeZBt5Y=";
window.testDevH = "BKjGppSCZCsL08YlF4MJcml6YkCglMvr56WlUOFjn9hOKXNa0iB9t8OHXW7lARIfYO0CZE/t1SlPA1mXdi/Rcjo=";
window.testSigG = "BGsX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfU=";
window.testSigH = "BPCEw7u8xI6vRpH90AotdOLWDjT5u2nsz73EVuqY9nq278CNnfOFVsIklsnvLya0qz3DEx05KYCHdbVy5TlY1L8=";
window.genBytes = [4, 107, 23, 209, 242, 225, 44, 66, 71, 248, 188, 230, 229, 99, 164, 64, 242, 119, 3, 125, 129, 45, 235, 51, 160, 244, 161, 57, 69, 216, 152, 194, 150, 79, 227, 66, 226, 254, 26, 127, 155, 142, 231, 235, 74, 124, 15, 158, 22, 43, 206, 51, 87, 107, 49, 94, 206, 203, 182, 64, 104, 55, 191, 81, 245];
window.hBytes = [4, 97, 25, 196, 70, 213, 45, 33, 189, 8, 106, 8, 111, 95, 39, 119, 7, 91, 32, 101, 186, 169, 186, 87, 156, 1, 140, 185, 141, 106, 90, 5, 193, 178, 251, 89, 7, 236, 175, 62, 91, 196, 188, 86, 40, 203, 15, 230, 241, 15, 49, 65, 124, 16, 47, 188, 65, 97, 15, 118, 139, 47, 130, 143, 161];
window.testTokensHkdf = JSON.parse(`[{"data":[237,20,250,80,161,8,37,128,78,147,159,160,227,23,161,220,22,137,228,182,45,72,175,25,57,126,251,158,253,246,209,1],"point":[4,96,37,164,31,129,161,96,198,72,207,232,253,202,164,46,95,125,167,167,16,85,248,226,63,29,199,228,32,74,184,75,112,80,67,186,92,112,0,18,62,31,208,88,21,10,77,55,151,0,143,87,168,178,83,119,102,217,65,156,115,150,186,82,121],"blind":[73,107,72,26,128,56,94,59,31,54,94,206,126,83,177,12,153,141,232,123,254,182,63,221,56,148,42,62,220,173,4,134]},{"data":[237,20,250,80,161,8,37,128,78,147,159,160,227,23,161,220,22,137,228,182,45,72,175,25,57,126,251,158,253,246,209,1],"point":[4,226,239,220,115,116,126,21,227,139,122,27,185,15,229,228,239,150,75,59,141,204,253,164,40,248,90,67,20,32,200,78,252,160,47,15,9,200,58,130,65,180,69,114,160,89,171,73,192,128,163,157,11,206,45,93,11,68,255,93,1,43,81,132,231],"blind":[73,107,72,26,128,56,94,59,31,54,94,206,126,83,177,12,153,141,232,123,254,182,63,221,56,148,42,62,220,173,4,134]}]`);
window.testTokensHkdfCompressed = JSON.parse(`[{"data":[237,20,250,80,161,8,37,128,78,147,159,160,227,23,161,220,22,137,228,182,45,72,175,25,57,126,251,158,253,246,209,1],"point":[3,96,37,164,31,129,161,96,198,72,207,232,253,202,164,46,95,125,167,167,16,85,248,226,63,29,199,228,32,74,184,75,112],"blind":[73,107,72,26,128,56,94,59,31,54,94,206,126,83,177,12,153,141,232,123,254,182,63,221,56,148,42,62,220,173,4,134]},{"data":[237,20,250,80,161,8,37,128,78,147,159,160,227,23,161,220,22,137,228,182,45,72,175,25,57,126,251,158,253,246,209,1],"point":[3,226,239,220,115,116,126,21,227,139,122,27,185,15,229,228,239,150,75,59,141,204,253,164,40,248,90,67,20,32,200,78,252],"blind":[73,107,72,26,128,56,94,59,31,54,94,206,126,83,177,12,153,141,232,123,254,182,63,221,56,148,42,62,220,173,4,134]}]`);

window.goodResponses = [
    {
        string: `signatures=WyJCTGZOdGZ6eG92RXdwZk5LWVBvRkk3dHNLNk5rMjNNalluUklEVFhGdHEwYm9zbWJIN1l1bERYWHVrdVYrKytxZyttYU9UWEF4cXpGSHNkV3p2dEpmQU09IiwiQkVIa1BPT1p3UlIrT0dNKzJQTUJnRWVrdUhobVJpVUlJSGxiaGJqNkNSKzZ2blp3Sk1CTHlNbDR4aURuOVY4SUhQNFdENFRaTUJGQjR0cStXd0c5azdRPSIsIkJBKzM4NkZPNkNXODZJbGIxdzdEOUZWMytwRnN
            SOEpjaC8rcWN2eVRpVTdFM3VONkUxZWJmVkloUjRDd3oxMWJHdlJhNzZhMGRWYlFhRjNZQUozR1Rmdz0iLCJZbUYwWTJndGNISnZiMlk5ZXlKRElqcGJJbEJyYVVVMlRXMXFiMGg0Vm1ZMmJFOXNiVEZvVDNWTFkxRjRZV1JMYlRacU0wZFNjV1Z0YkhOWFQwMDlJaXdpTUZWRFIwZDRRbEZvY0ZCc2VWQnZkV05ITlZkU01sWnJOa2RTTlZCMFQxZG1hVWxPY25sRmNUVmlUVDBpTENKdVJqSkVXV2
            xvVG1wNmJrc3ZUazFvWWxOa1MySndhbkpGTkdzMlZFaEVNR2hEVjJkeVFYRlpRMHBSUFNKZExDSk5JanBiSWtKTVNqTkpiRkprUm5kbUwwaDFhVzFDV1RWMWJXSkpaM2h1U1dWYWJGbzFkekY2VjJ0R1UySlFaWFJsTkN0MFRFaHpXbU42ZFhKRlZtMXZRVlIzTkVvMFZDODFUMjkwYTBaWVdFUjZUMFV4TWxrell6UkRUVDBpTENKQ1R6QXJhbVZVV0ZCUVEwSklVMUZvTTNNeFRVWnNhblZMWlc5d
            VNGWjNSREJ2ZVN0NVFrMUlaa292VkZaSlpFVXJRbkl2V1doellsRk1ObkIyVlRSaU1URlJVVEIyTTA5R2MwdHZjRmx5YTBSa1VFeHlXVTA5SWl3aVFrRklXa1owVVVNeFlYbzFOVUU0TlhVNVRHZFNaVWdyVVRoTmJGUTNNMFpMZDBVMU1WVkthMlJ1WW5aTFdrWkljMlJTVkVkVVprZDRhV2gxU0ZwMU9WVm9SVXh1UVZKcVVFdHBaSFJ3ZVRkd2EyWTNjMHc0UFNKZExDSlFJam9pWlhsS1NFbHFi
            MmxSYXpsd1drVldNVlI2YkVsVk1IQjZWRlp3V2xKVE9WRmFiVTB4VWtOemQxSlZlSFZOUjBwNFlVZHdSbHBYV1hsVWVrSXhTekIwUW1SNlRtMVZSVEZKVTBab01GWnRlRVpSYmxwYVlXdFZNVk5UT1ZCVWJWazFWVE5zVlZKc1RuSlRSRTUwVkVVMVNXRXhUWGRPYTFJeFRtMW9VbEJUU1hOSmF6QnBUMmxLUTFKRVVtbFdWbGt4Wld0MGRsWkZkSFJPYTJSNldrVmFiR0pVYUZOYVJHUjBaVVpCZWx
            ZeVduaFRXRUUxV1ROT2RXSllUa3hUYWxaVlpVTTVTbFZXUm05YU1HUk5Zek5TTUZKcmNESmliSEJGWlZWd1YwNHhjSEZQVlVaNVducEdSMU5WY0dwbGFrMTNXbFZrTW1Kc1RsUmFiazA1U1dsM2FWTkRTVFpKYTBwSlZERkNUMUZXWkZsVmJXc3dZMms1VDFKWVFqQlVNbXhOVkROQk5GUldUak5aTVdkM1pHdG9lVlpyVWxOWFNGbDRUbXR3ZFdJelpHcE5WMVpaVjBjNE1XVkZXa2RUTUd4UVUxUm
            FkRlpZUVRSaGVtdDJXbGRPYUU1V1dscE5SR1JyVVcxb1FscFVhRkphYkVsMlVteE9VMWRVTUdsTVEwcGhTV3B2YVZGcmRFeFhWRnBIWVhwQ01tTXlOVUpTYTFvelpHMW5NVTR5VG10YVdFcHZaVWhCZUdRd2IzWk5NSGg2VWpGd05FNXVhSEpWVkUweVZsUktVbFpzVmxGU01GSnlaVmMxZUZkR1NuVlNhMHBwWTJsemNtVnRhSEJqVlZwSFRWTTRNMU51UVROWFZrNTZVakowVDJOSFpFcFdTRkpxV
            UZOSmMwbHNTV2xQYVVvMVVsTjBiRTFYWkVWV2FrcHBUbGhhVEdORVFsZFdXR3cxVFVSb1RGUjZVVFJsUldoSFZteEtiMVZGVG0xaFZteDFWVmRPVW1NeU1XcFFVMGx6U1d0TmFVOXBTbGhsYWsxeVZtcHNjazVyVGpKalJUbGFZa1puTWs0elduVmpNbHBzVlZVMWNsZHJOVmhXU0VwWFUwUkJOVmRGU2xwVk0yaE1ZWHBDVmxCVFNqa2lMQ0phSWpwYklrSk1aazUwWm5wNGIzWkZkM0JtVGt0WlVH
            OUdTVGQwYzBzMlRtc3lNMDFxV1c1U1NVUlVXRVowY1RCaWIzTnRZa2czV1hWc1JGaFlkV3QxVmlzckszRm5LMjFoVDFSWVFYaHhla1pJYzJSWGVuWjBTbVpCVFQwaUxDSkNSVWhyVUU5UFduZFNVaXRQUjAwck1sQk5RbWRGWld0MVNHaHRVbWxWU1VsSWJHSm9ZbW8yUTFJck5uWnVXbmRLVFVKTWVVMXNOSGhwUkc0NVZqaEpTRkEwVjBRMFZGcE5Ra1pDTkhSeEsxZDNSemxyTjFFOUlpd2lRa0V
            yTXpnMlJrODJRMWM0Tmtsc1lqRjNOMFE1UmxZekszQkdjMUk0U21Ob0x5dHhZM1o1VkdsVk4wVXpkVTQyUlRGbFltWldTV2hTTkVOM2VqRXhZa2QyVW1FM05tRXdaRlppVVdGR00xbEJTak5IVkdaM1BTSmRmUT09Il0=`,
        name: "old",
    },
    {
        string: `signatures=ewogICAgInNpZ3MiOiBbCiAgICAgICAgIkJMZk50Znp4b3ZFd3BmTktZUG9GSTd0c0s2TmsyM01qWW5SSURUWEZ0cTBib3NtYkg3WXVsRFhYdWt1VisrK3FnK21hT1RYQXhxekZIc2RXenZ0SmZBTT0iLAogICAgICAgICJCRUhrUE9PWndSUitPR00rMlBNQmdFZWt1SGhtUmlVSUlIbGJoYmo2Q1IrNnZuWndKTUJMeU1sNHhpRG45VjhJSFA0V0Q0VFpNQkZCNHRxK1d3RzlrN1E
            9IiwKICAgICAgICAiQkErMzg2Rk82Q1c4NklsYjF3N0Q5RlYzK3BGc1I4SmNoLytxY3Z5VGlVN0UzdU42RTFlYmZWSWhSNEN3ejExYkd2UmE3NmEwZFZiUWFGM1lBSjNHVGZ3PSIKICAgIF0sCiAgICAicHJvb2YiOiAiWW1GMFkyZ3RjSEp2YjJZOWV5SkRJanBiSWxCcmFVVTJUVzFxYjBoNFZtWTJiRTlzYlRGb1QzVkxZMUY0WVdSTGJUWnFNMGRTY1dWdGJITlhUMDA5SWl3aU1GVkRSMGQ0UWxGb2NGQn
            NlVkJ2ZFdOSE5WZFNNbFpyTmtkU05WQjBUMWRtYVVsT2NubEZjVFZpVFQwaUxDSnVSakpFV1dsb1RtcDZia3N2VGsxb1lsTmtTMkp3YW5KRk5HczJWRWhFTUdoRFYyZHlRWEZaUTBwUlBTSmRMQ0pOSWpwYklrSk1Tak5KYkZKa1JuZG1MMGgxYVcxQ1dUVjFiV0pKWjNodVNXVmFiRm8xZHpGNlYydEdVMkpRWlhSbE5DdDBURWh6V21ONmRYSkZWbTF2UVZSM05FbzBWQzgxVDI5MGEwWllXRVI2VDBVeE1sa
            3pZelJEVFQwaUxDSkNUekFyYW1WVVdGQlFRMEpJVTFGb00zTXhUVVpzYW5WTFpXOXVTRlozUkRCdmVTdDVRazFJWmtvdlZGWkpaRVVyUW5JdldXaHpZbEZNTm5CMlZUUmlNVEZSVVRCMk0wOUdjMHR2Y0ZseWEwUmtVRXh5V1UwOUlpd2lRa0ZJV2taMFVVTXhZWG8xTlVFNE5YVTVUR2RTWlVnclVUaE5iRlEzTTBaTGQwVTFNVlZLYTJSdVluWkxXa1pJYzJSU1ZFZFVaa2Q0YVdoMVNGcDFPVlZvUlV4dVFW
            SnFVRXRwWkhSd2VUZHdhMlkzYzB3NFBTSmRMQ0pRSWpvaVpYbEtTRWxxYjJsUmF6bHdXa1ZXTVZSNmJFbFZNSEI2VkZad1dsSlRPVkZhYlUweFVrTnpkMUpWZUhWTlIwcDRZVWR3UmxwWFdYbFVla0l4U3pCMFFtUjZUbTFWUlRGSlUwWm9NRlp0ZUVaUmJscGFZV3RWTVZOVE9WQlViVmsxVlROc1ZWSnNUbkpUUkU1MFZFVTFTV0V4VFhkT2ExSXhUbTFvVWxCVFNYTkphekJwVDJsS1ExSkVVbWxXVmxreFp
            XdDBkbFpGZEhST2EyUjZXa1ZhYkdKVWFGTmFSR1IwWlVaQmVsWXlXbmhUV0VFMVdUTk9kV0pZVGt4VGFsWlZaVU01U2xWV1JtOWFNR1JOWXpOU01GSnJjREppYkhCRlpWVndWMDR4Y0hGUFZVWjVXbnBHUjFOVmNHcGxhazEzV2xWa01tSnNUbFJhYmswNVNXbDNhVk5EU1RaSmEwcEpWREZDVDFGV1pGbFZiV3N3WTJrNVQxSllRakJVTW14TlZETkJORlJXVGpOWk1XZDNaR3RvZVZaclVsTlhTRmw0VG10d2
            RXSXpaR3BOVjFaWlYwYzRNV1ZGV2tkVE1HeFFVMVJhZEZaWVFUUmhlbXQyV2xkT2FFNVdXbHBOUkdSclVXMW9RbHBVYUZKYWJFbDJVbXhPVTFkVU1HbE1RMHBoU1dwdmFWRnJkRXhYVkZwSFlYcENNbU15TlVKU2Exb3paRzFuTVU0eVRtdGFXRXB2WlVoQmVHUXdiM1pOTUhoNlVqRndORTV1YUhKVlZFMHlWbFJLVWxac1ZsRlNNRkp5WlZjMWVGZEdTblZTYTBwcFkybHpjbVZ0YUhCalZWcEhUVk00TTFOd
            VFUTlhWazU2VWpKMFQyTkhaRXBXU0ZKcVVGTkpjMGxzU1dsUGFVbzFVbE4wYkUxWFpFVldha3BwVGxoYVRHTkVRbGRXV0d3MVRVUm9URlI2VVRSbFJXaEhWbXhLYjFWRlRtMWhWbXgxVlZkT1VtTXlNV3BRVTBselNXdE5hVTlwU2xobGFrMXlWbXBzY2s1clRqSmpSVGxhWWtabk1rNHpXblZqTWxwc1ZWVTFjbGRyTlZoV1NFcFhVMFJCTlZkRlNscFZNMmhNWVhwQ1ZsQlRTamtpTENKYUlqcGJJa0pNWms1
            MFpucDRiM1pGZDNCbVRrdFpVRzlHU1RkMGMwczJUbXN5TTAxcVdXNVNTVVJVV0VaMGNUQmliM050WWtnM1dYVnNSRmhZZFd0MVZpc3JLM0ZuSzIxaFQxUllRWGh4ZWtaSWMyUlhlblowU21aQlRUMGlMQ0pDUlVoclVFOVBXbmRTVWl0UFIwMHJNbEJOUW1kRlpXdDFTR2h0VW1sVlNVbEliR0pvWW1vMlExSXJOblp1V25kS1RVSk1lVTFzTkhocFJHNDVWamhKU0ZBMFYwUTBWRnBOUWtaQ05IUnhLMWQzUnp
            sck4xRTlJaXdpUWtFck16ZzJSazgyUTFjNE5rbHNZakYzTjBRNVJsWXpLM0JHYzFJNFNtTm9MeXR4WTNaNVZHbFZOMFV6ZFU0MlJURmxZbVpXU1doU05FTjNlakV4WWtkMlVtRTNObUV3WkZaaVVXRkdNMWxCU2pOSFZHWjNQU0pkZlE9PSIKfQ==`,
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
