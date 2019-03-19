import atob from "atob";
import btoa from "btoa";
import createShake256 from "../src/crypto/keccak/keccak";
import rewire from "rewire";

let localStorageItems = new Map;
let spentUrl = new Map;
let spendId = new Map;
let spentTab = new Map;
let spentHosts = new Map;
let timeSinceLastResp = 0;

window.localStorageItems = localStorageItems;
window.spentUrl = spentUrl;
window.spendId = spendId;
window.spentTab = spentTab;
window.spentHosts = spentHosts;
window.timeSinceLastResp = 0;

window.workflowSet = () => {

    let workflow = rewire("../addon/compiled/test_compiled.js");

    workflow.__set__("get", get);
    workflow.__set__("set", set);

    workflow.__set__("localStorage", localStorageMock);
    workflow.__set__("localStorageItems", localStorageItems);
    workflow.__set__("updateIcon", updateIconMock);
    workflow.__set__("updateBrowserTab", updateBrowserTabMock);
    workflow.__set__("atob", atob);
    workflow.__set__("btoa", btoa);

    workflow.__set__("setSpendFlag", setSpendFlag);
    workflow.__set__("getSpendFlag", getSpendFlag);

    workflow.__set__("spentUrl", spentUrl);
    workflow.__set__("setSpentUrl", setSpentUrl);
    workflow.__set__("getSpentUrl", getSpentUrl);

    workflow.__set__("spendId", spendId);
    workflow.__set__("setSpendId", setSpendId);
    workflow.__set__("getSpendId", getSpendId);

    workflow.__set__("spentTab", spentTab);
    workflow.__set__("setSpentTab", setSpentTab);
    workflow.__set__("getSpentTab", getSpentTab);


    workflow.__set__("spentHosts", spentHosts);
    workflow.__set__("setSpentHosts", setSpentHosts);
    workflow.__set__("getSpentHosts", getSpentHosts);

    workflow.__set__("createShake256", createShake256);
    workflow.__set__("clearCachedCommitments", clearCachedCommitments);
    workflow.__set__("timeSinceLastResp", timeSinceLastResp);

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

window.CACHED_COMMITMENTS_STRING = "cached-commitments";
window.clearCachedCommitments = () => set(CACHED_COMMITMENTS_STRING, null);

window.setSpendFlag = (key, value) => set(key, value);
window.getSpendFlag = (key) => get(key)

window.get = (key) => JSON.parse(localStorage.getItem(key));
window.set = (key, value) => localStorage.setItem(key, JSON.stringify(value));
window.clearLocalStorage = () => localStorage.clear()

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

let storedTokens = JSON.stringify([{
    "data": [24, 62, 56, 102, 76, 127, 201, 111, 161, 218, 249, 109, 34, 122, 160, 219, 93, 186, 246, 12, 178, 249, 241, 108, 69, 181, 77, 140, 158, 13, 216, 184],
    "point": "/MWxehOPdGROly7JRQxXp4G8WRzMHTqIjtc17kXrk6W4i2nIp3QRv3/1EVQAeJfmTvIwVUgJTMI3KhGQ4pSNTQ==",
    "blind": "0x46af9794d53f040607a35ad297f92aef6a9879686279a12a0a478b2e0bde9089"
}, {
    "data": [131, 120, 153, 53, 158, 58, 11, 155, 160, 109, 247, 176, 176, 153, 14, 161, 150, 120, 43, 180, 188, 37, 35, 75, 52, 219, 177, 16, 24, 101, 241, 159],
    "point": "sn4KWtjU+RL7aE53zp4wUdhok4UU9iZTAwQVVAmBoGA+XltG/E3V5xIKZ1fxDs0qhbFG1ujXajYUt831rQcCug==",
    "blind": "0xd475b86c84c94586503f035911388dd702f056472a755e964cbbb3b58c76bd53"
}]);
const testG = "BOidEuO9HSJsMZYE/Pfc5D+0ELn0bqhjEef2O0u+KAw3fPMHHXtVlEBvYjE5I/ONf9SyTFSkH3mLNHkS06Du6hQ=";
const testH = "BHOPNAWXRi4r/NEptOiLOp8MSwcX0vHrVDRXv16Jnowc1eXXo5xFFKIOI6mUp8k9/eca5VY07dBhAe8QfR/FSRY=";
const testDevG = "BIpWWWWFtDRODAHEzZlvjKyDwQAdh72mYKMAsGrtwsG7XmMxsy89gfiOFbX3RZ9Ik6jEYWyJB0TmnWNVeeZBt5Y=";
const testDevH = "BKjGppSCZCsL08YlF4MJcml6YkCglMvr56WlUOFjn9hOKXNa0iB9t8OHXW7lARIfYO0CZE/t1SlPA1mXdi/Rcjo=";

window.testG = testG;
window.testH = testH;
window.testDevG = testDevG;
window.testDevH = testDevH;
window.storedTokens = storedTokens;

window.getSpentUrl = (key) => spentUrl[key];
window.setSpentUrl = (key, value) => spentUrl[key] = value;

window.getSpendId = (key) => spendId[key];
window.setSpendId = (key, value) => spendId[key] = value;

window.getSpentTab = (key) => spentTab[key];
window.setSpentTab = (key, value) => spentTab[key] = value;
window.clearSpentTab = () => spentTab = new Map();

window.getSpentHosts = (key) => spentHosts[key];
window.setSpentHosts = (key, value) => spentHosts[key] = value;
window.clearSpentHOsts = () => spentHosts = new Map();

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
    this.responseText = `{"CF":{"dev":{"G": "` + testDevG + `","H": "` + testDevH + `"},"1.0":{"G":"` + testG + `","H":"` + testH + `"},"1.1":{"G":"new_11_commitment_g","H":"new_11_commitment_h"}}}`;
}

window.mockXHRCommitments = mockXHRCommitments;

window.setTimeSinceLastResp = (value) => timeSinceLastResp = value;