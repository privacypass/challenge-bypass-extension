/**
* Integrations tests for when headers are sent by the browser
* 
* @author: Alex Davidson
*/
import btoa from "btoa";
import atob from "atob";
import createShake256 from "../addon/scripts/keccak.js"

import rewire from "rewire";
var workflow = rewire("../addon/compiled/test_compiled.js");
var URL = window.URL;

/**
* Functions/variables
*/
const EXAMPLE_HREF = "https://example.com";
const CAPTCHA_HREF = "https://captcha.website";
const EXAMPLE_SUFFIX = "/cdn-cgi/l/chk_captcha?id=4716480f5bb534e8&g-recaptcha-response=03AMGVjXh24S6n8-HMQadfr8AmSr-2i87s1TTWUrhfnrIcti9hw1DigphUtiZzhU5R44VlJ3CmoH1W6wZaqde7iJads2bFaErY2bok29QfgZrbhO8q6UBbwLMkVlZ803M1UyDYhA9xYJqLR4kVtKhrHkDsUEKN4vXKc3CNxQpysmvdTqdt31Lz088ptkkksGLzRluDu-Np11ER6NX8XaH2S4iwIR823r3txm4eaMoEeoLfOD5S_6WHD5RhH0B7LRa_l7Vp5ksEB-0vyHQPLQQLOYixrC_peP3dG3dnaTY5UcUAUxZK4E74glzCu2PyRpKNnQ9akFz-niWiFCY0z-cuJeOArMvGOQCC9Q";
const CAPTCHA_BYPASS_SUFFIX = "&captcha-bypass=true";
const beforeRequest = workflow.__get__('beforeRequest');
const sendXhrSignReq = workflow.__get__('sendXhrSignReq');
const BuildIssueRequest = workflow.__get__('BuildIssueRequest');
const getBigNumFromBytes = workflow.__get__('getBigNumFromBytes');
const sec1DecodePointFromBytes = workflow.__get__('sec1DecodePointFromBytes');
const setConfig = workflow.__get__('setConfig');
let localStorage;
let details;
let url;
let respText = `signatures=WyJCTGZOdGZ6eG92RXdwZk5LWVBvRkk3dHNLNk5rMjNNalluUklEVFhGdHEwYm9zbWJIN1l1bERYWHVrdVYrKytxZyttYU9UWEF4cXpGSHNkV3p2dEpmQU09IiwiQkVIa1BPT1p3UlIrT0dNKzJQTUJnRWVrdUhobVJpVUlJSGxiaGJqNkNSKzZ2blp3Sk1CTHlNbDR4aURuOVY4SUhQNFdENFRaTUJGQjR0cStXd0c5azdRPSIsIkJBKzM4NkZPNkNXODZJbGIxdzdEOUZWMytwRnN
SOEpjaC8rcWN2eVRpVTdFM3VONkUxZWJmVkloUjRDd3oxMWJHdlJhNzZhMGRWYlFhRjNZQUozR1Rmdz0iLCJZbUYwWTJndGNISnZiMlk5ZXlKRElqcGJJbEJyYVVVMlRXMXFiMGg0Vm1ZMmJFOXNiVEZvVDNWTFkxRjRZV1JMYlRacU0wZFNjV1Z0YkhOWFQwMDlJaXdpTUZWRFIwZDRRbEZvY0ZCc2VWQnZkV05ITlZkU01sWnJOa2RTTlZCMFQxZG1hVWxPY25sRmNUVmlUVDBpTENKdVJqSkVXV2
xvVG1wNmJrc3ZUazFvWWxOa1MySndhbkpGTkdzMlZFaEVNR2hEVjJkeVFYRlpRMHBSUFNKZExDSk5JanBiSWtKTVNqTkpiRkprUm5kbUwwaDFhVzFDV1RWMWJXSkpaM2h1U1dWYWJGbzFkekY2VjJ0R1UySlFaWFJsTkN0MFRFaHpXbU42ZFhKRlZtMXZRVlIzTkVvMFZDODFUMjkwYTBaWVdFUjZUMFV4TWxrell6UkRUVDBpTENKQ1R6QXJhbVZVV0ZCUVEwSklVMUZvTTNNeFRVWnNhblZMWlc5d
VNGWjNSREJ2ZVN0NVFrMUlaa292VkZaSlpFVXJRbkl2V1doellsRk1ObkIyVlRSaU1URlJVVEIyTTA5R2MwdHZjRmx5YTBSa1VFeHlXVTA5SWl3aVFrRklXa1owVVVNeFlYbzFOVUU0TlhVNVRHZFNaVWdyVVRoTmJGUTNNMFpMZDBVMU1WVkthMlJ1WW5aTFdrWkljMlJTVkVkVVprZDRhV2gxU0ZwMU9WVm9SVXh1UVZKcVVFdHBaSFJ3ZVRkd2EyWTNjMHc0UFNKZExDSlFJam9pWlhsS1NFbHFi
MmxSYXpsd1drVldNVlI2YkVsVk1IQjZWRlp3V2xKVE9WRmFiVTB4VWtOemQxSlZlSFZOUjBwNFlVZHdSbHBYV1hsVWVrSXhTekIwUW1SNlRtMVZSVEZKVTBab01GWnRlRVpSYmxwYVlXdFZNVk5UT1ZCVWJWazFWVE5zVlZKc1RuSlRSRTUwVkVVMVNXRXhUWGRPYTFJeFRtMW9VbEJUU1hOSmF6QnBUMmxLUTFKRVVtbFdWbGt4Wld0MGRsWkZkSFJPYTJSNldrVmFiR0pVYUZOYVJHUjBaVVpCZWx
ZeVduaFRXRUUxV1ROT2RXSllUa3hUYWxaVlpVTTVTbFZXUm05YU1HUk5Zek5TTUZKcmNESmliSEJGWlZWd1YwNHhjSEZQVlVaNVducEdSMU5WY0dwbGFrMTNXbFZrTW1Kc1RsUmFiazA1U1dsM2FWTkRTVFpKYTBwSlZERkNUMUZXWkZsVmJXc3dZMms1VDFKWVFqQlVNbXhOVkROQk5GUldUak5aTVdkM1pHdG9lVlpyVWxOWFNGbDRUbXR3ZFdJelpHcE5WMVpaVjBjNE1XVkZXa2RUTUd4UVUxUm
FkRlpZUVRSaGVtdDJXbGRPYUU1V1dscE5SR1JyVVcxb1FscFVhRkphYkVsMlVteE9VMWRVTUdsTVEwcGhTV3B2YVZGcmRFeFhWRnBIWVhwQ01tTXlOVUpTYTFvelpHMW5NVTR5VG10YVdFcHZaVWhCZUdRd2IzWk5NSGg2VWpGd05FNXVhSEpWVkUweVZsUktVbFpzVmxGU01GSnlaVmMxZUZkR1NuVlNhMHBwWTJsemNtVnRhSEJqVlZwSFRWTTRNMU51UVROWFZrNTZVakowVDJOSFpFcFdTRkpxV
UZOSmMwbHNTV2xQYVVvMVVsTjBiRTFYWkVWV2FrcHBUbGhhVEdORVFsZFdXR3cxVFVSb1RGUjZVVFJsUldoSFZteEtiMVZGVG0xaFZteDFWVmRPVW1NeU1XcFFVMGx6U1d0TmFVOXBTbGhsYWsxeVZtcHNjazVyVGpKalJUbGFZa1puTWs0elduVmpNbHBzVlZVMWNsZHJOVmhXU0VwWFUwUkJOVmRGU2xwVk0yaE1ZWHBDVmxCVFNqa2lMQ0phSWpwYklrSk1aazUwWm5wNGIzWkZkM0JtVGt0WlVH
OUdTVGQwYzBzMlRtc3lNMDFxV1c1U1NVUlVXRVowY1RCaWIzTnRZa2czV1hWc1JGaFlkV3QxVmlzckszRm5LMjFoVDFSWVFYaHhla1pJYzJSWGVuWjBTbVpCVFQwaUxDSkNSVWhyVUU5UFduZFNVaXRQUjAwck1sQk5RbWRGWld0MVNHaHRVbWxWU1VsSWJHSm9ZbW8yUTFJck5uWnVXbmRLVFVKTWVVMXNOSGhwUkc0NVZqaEpTRkEwVjBRMFZGcE5Ra1pDTkhSeEsxZDNSemxyTjFFOUlpd2lRa0V
yTXpnMlJrODJRMWM0Tmtsc1lqRjNOMFE1UmxZekszQkdjMUk0U21Ob0x5dHhZM1o1VkdsVk4wVXpkVTQyUlRGbFltWldTV2hTTkVOM2VqRXhZa2QyVW1FM05tRXdaRlppVVdGR00xbEJTak5IVkdaM1BTSmRmUT09Il0=`;
let respBadProof = `signatures=WyJCQVRkL01qTnNuTTZxaHBQZzFLS216RnVHOUNQRzdFbERVSU5EVjFJQmd5WTN2RkVrdENUMk8ybW82dGNNLy9qMWE2Zkoyb1dMb2Z5MGZqYWVjTlBEeWM9IiwiQk9aQnY4dnNxdFg3VzRKcFlSZERHMm5QSEtHTDBMVUtFY1VCY1ZTZjcrcnlxRHRRdC9WZFFlZHRLMkVNa1AvMXZvcjl6dkkvRDZ0ekNZQi9CQkRLRkpRPSIsIkJNMW9UdW9Bc3RiTzQvN3ZIcUEwaDhNbG5
rNG5UdEJ6NzdvN25RWitqM2RhQ09FU3RXM1VTWHRKdGdmcnVramZBNkxDUksyUmpFVGZVUWU1cmhpaEY0ND0iLCJZbUYwWTJndGNISnZiMlk5ZXlKRElqcGJJbXhrWldacVJ6QXZaRXh2VUhVdkt6UjNURkl5TTJaM2JsWllWVGQwY1dSYU5uSmhlbWhqYTNSa1JYYzlJaXdpZWt4M2QyZHROVGxaU0c5T2FtRkVhVkJ5UzBSd1VrOU5ZMnBsTlhwc2IxaEtXa2MyY1ZJMGJUQXhRVDBpTENKbl
IzTnBTRE5XYkRGRVMwVjFaMjl1VVRoRmVFODVaRkkxU0Voc05HUTBNMmRGUWpWd04wUkRhV3BSUFNKZExDSk5JanBiSWtKSU5VSndZVkpUZEdwWkwwMXNNMVVyUW5aREwzUjNaRzVpVldzMVdFZG9Nbk5rZUZOV09HWkJkR2cyWXpKaFlreHhZV1o2Y2pKcEsySm5kVTVpS3l0Mk0xaEVOV3RHTWt0V2JFaGtSamxzYTNwNmRtVTVhejBpTENKQ1RIWTFZM2hwVlZscVRWbEdiMHczY1VGWmVTO
TBiSGRsUmtGeGRrWlBiVEZQWVZFeFVIVnJaRUZYWTB0NFpqZEpaekZWU0VoR05saENOMWxuVVd0dVFrOTVkSHBwYTNsUGFFZHpUbmcyYjFoMFZHbGFVRms5SWl3aVFsQTVLMkZUWlZKbU9XbDZNRGsyWm5Gb1NreHNTMFIwYjFORVRTdDFVVUpOVVVobGJHVktia1prZUdzMWRURnViRlF2VDFrNVZsaEdSM0JvYWxWSGJGSkllRW92UTJoaVZrdDNSVGwxZG1KSmJYWnhjWGxSUFNKZExDSlFJ
am9pWlhsS1NFbHFiMmxSYXpsd1drVldNVlI2YkVsVk1IQjZWRlp3V2xKVE9WRmFiVTB4VWtOemQxSlZlSFZOUjBwNFlVZHdSbHBYV1hsVWVrSXhTekIwUW1SNlRtMVZSVEZKVTBab01GWnRlRVpSYmxwYVlXdFZNVk5UT1ZCVWJWazFWVE5zVlZKc1RuSlRSRTUwVkVVMVNXRXhUWGRPYTFJeFRtMW9VbEJUU1hOSmF6QnBUMmxLUTFGV1drOWlhMmhQWTI1c1NWcFlRbnBPUmtKNlZsZFdTMUp
xYTNkWlZGSldWbXhyZWxkclVqTlNWa0pRV2tWck5WRnROV3hoZW1oRVUwYzVXRkp0VlhaWGJUbFNUMWRrY0ZadFJuSlVSa0o1VjBoQmVVNUdRbEZqUlVwSVVXeGtiV0pGV25aVE1IQnFWa2RrVTFWdFJYSk5SVlU1U1dsM2FWTkRTVFpKYTBwSlZERkNUMUZXWkZsVmJXc3dZMms1VDFKWVFqQlVNbXhOVkROQk5GUldUak5aTVdkM1pHdG9lVlpyVWxOWFNGbDRUbXR3ZFdJelpHcE5WMVpaVj
BjNE1XVkZXa2RUTUd4UVUxUmFkRlpZUVRSaGVtdDJXbGRPYUU1V1dscE5SR1JyVVcxb1FscFVhRkphYkVsMlVteE9VMWRVTUdsTVEwcGhTV3B2YVZGclJrbE9SMVY2WlZkU05WRlhXbXBVYm1jMVlYcGplVlJJU2tKaVJ6bGFWREJHYVdGc1RsQlNSM2Q0V2pGU1ZHRnFXbXRqTVVGNVN6TkNOVkpZVWxGWFJHd3pWWHBPU1ZSNlVrNU5iazVNWkZkT01GTXdSazFUTW14MllVaHdlRTR5V1RGa
mFrcFhVekJKTUU5SVJraE5SR3hXVUZOSmMwbHNTV2xQYVVwTVlVWk9WMVpYY0V0aVZHaFlZMFJDTUU5RVRuRk9NRlpTV1hwa00xSkZhekZYYkU1NFRWUkNVRTlIWkROVlJHYzBaRE5XVTFwWVFuSlFVMGx6U1d0TmFVOXBTa2xXUjFaTFZWVTVOVkZVVWxaV2F6RlRVbFJXVmxkRldqWlhiRWt5Wkd4d1RsSkZkSHBsYVhSelYwVXhkMk5IZERGYVJGWlBVbGhPVGxCVFNqa2lMQ0phSWpwYklr
SkJTemhFUVU1bU9HRldjSEZtVVZoS1J5dFZkQzlJWVZOeU5XWmpaVnB1WlVkbmNFMXRaR0ZLUTNNeVUya3dVbWRaVm5sNWNERlVUU3RwTTBaa01VRkhWMmgyYVdKNFRYcG9SbVY1WTFOc0swSXZkMmR2YXowaUxDSkNSMWc0YjFFeVpGRkpjV1ZLZEZwMGNtOWthM1E1YlhKdFJtaEJiVWRWVUZsbGVWVTNVRGRqWlRsVWRURm9LM0F3Vm1oTFZXbFpVek13WkVRclVua3JjVVZSYm05VE5FSjZ
jRmhpUmxoUFkzQnhhM0JIVjJjOUlpd2lRa2RzUWpWak4yaFBaWE5GZEU5U2VYRldiREZHVFRkR1ozcHZNR3QzVlhwQ2FYRnNhVkZSVEVScVN6TnhiRGw0UWxaaFJrZHRhREIwVVdSYWNsTnJXR3A0VTB4dWVVZHNiRk5wT0ZwWVJYazROMjFOVDBGRlBTSmRmUT09Il0=`;
let testTokens = JSON.parse(`[{"token":[237,20,250,80,161,8,37,128,78,147,159,160,227,23,161,220,22,137,228,182,45,72,175,25,57,126,251,158,253,246,209,1],"point":[4,178,119,34,84,93,23,7,255,30,232,166,5,142,110,153,178,32,198,114,30,102,86,121,195,92,214,144,84,155,61,235,94,227,235,75,30,198,92,206,234,196,86,106,0,79,14,9,225,63,249,58,139,100,21,117,195,204,225,53,217,141,220,224,35],"blind":[73,107,72,26,128,56,94,59,31,54,94,206,126,83,177,12,153,141,232,123,254,182,63,221,56,148,42,62,220,173,4,134]},{"token":[254,122,184,29,171,157,229,38,101,187,66,154,255,160,164,128,17,142,250,241,176,89,123,12,53,24,236,91,58,3,212,217],"point":[4,237,62,141,228,215,60,240,129,29,36,33,222,205,76,22,88,238,41,234,39,29,92,3,210,140,190,200,19,7,124,159,211,84,135,68,248,26,255,98,27,27,64,190,169,189,78,27,215,84,16,210,253,206,22,194,168,165,138,228,13,211,203,173,131],"blind":[44,0,207,19,25,28,76,114,193,226,49,111,160,152,161,102,207,170,195,9,31,220,120,202,182,50,135,83,7,2,134,21]},{"token":[223,42,23,79,237,61,125,106,86,135,234,109,171,67,86,202,166,142,77,238,69,175,78,67,214,214,246,171,20,178,166,251],"point":[4,1,217,22,212,2,213,172,249,228,15,57,187,210,224,69,225,254,67,195,37,79,189,197,43,1,57,213,66,100,118,118,239,41,145,71,177,212,83,25,55,198,198,40,110,29,155,189,82,17,11,156,4,99,60,168,157,182,156,187,166,71,251,176,191],"blind":[74,150,233,91,28,35,116,26,6,87,77,9,8,200,166,69,152,61,192,210,236,207,68,138,250,104,16,195,92,232,43,132]}]`);

/* mock impls */
function setActiveCommitmentsMock() {}
workflow.__set__("setActiveCommitments", setActiveCommitmentsMock);
function getMock(key) {
    return localStorage[key];
}
function setMock(key, value) {
    localStorage[key] = value; 
}
function getSpendFlag(key) {
    return getMock(key);
}
function setSpendFlag(key, value) {
    setMock(key, value);
}
const updateIconMock = jest.fn();
const updateBrowserTabMock = jest.fn();

/* mock XHR implementations */
function mockXHR(_xhr) {
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
    _xhr.body;
    _xhr.send = function(str) {
        _xhr.body = str;
    }
    _xhr.onreadystatechange = function() {};
}

function mockXHRGood() {
    mockXHR(this);
    this.status = 200;
    this.readyState = 4;
}

function mockXHRBadStatus() {
    mockXHR(this);
    this.status = 403;
    this.readyState = 4;
}

function mockXHRBadReadyState() {
    mockXHR(this);
    this.status = 200;
    this.readyState = 5;
}

let _xhr;

beforeEach(() => {
    let storedTokens = `[ { "token":[24,62,56,102,76,127,201,111,161,218,249,109,34,122,160,219,93,186,246,12,178,249,241,108,69,181,77,140,158,13,216,184],"point":"/MWxehOPdGROly7JRQxXp4G8WRzMHTqIjtc17kXrk6W4i2nIp3QRv3/1EVQAeJfmTvIwVUgJTMI3KhGQ4pSNTQ==","blind":"0x46af9794d53f040607a35ad297f92aef6a9879686279a12a0a478b2e0bde9089"},{"token":[131,120,153,53,158,58,11,155,160,109,247,176,176,153,14,161,150,120,43,180,188,37,35,75,52,219,177,16,24,101,241,159],"point":"sn4KWtjU+RL7aE53zp4wUdhok4UU9iZTAwQVVAmBoGA+XltG/E3V5xIKZ1fxDs0qhbFG1ujXajYUt831rQcCug==","blind":"0xd475b86c84c94586503f035911388dd702f056472a755e964cbbb3b58c76bd53" } ]`;
    localStorage = {
        "bypass-tokens-1": storedTokens,
        "bypass-tokens-count-1": 2
    }
    details = {
        method: "GET",
        requestHeaders: [],
        requestId: "212",
        tabId: "101"
    };
    url = new URL(EXAMPLE_HREF);
    _xhr = mockXHRGood;
    setMockFunctions();
    setXHR(_xhr);
    setTimeSinceLastResp(Date.now());
    setConfig(1); // set the CF config
    // Mock the active commitments because XHR is not available
    workflow.__set__("activeG", "BOidEuO9HSJsMZYE/Pfc5D+0ELn0bqhjEef2O0u+KAw3fPMHHXtVlEBvYjE5I/ONf9SyTFSkH3mLNHkS06Du6hQ=");
    workflow.__set__("activeH", "BHOPNAWXRi4r/NEptOiLOp8MSwcX0vHrVDRXv16Jnowc1eXXo5xFFKIOI6mUp8k9/eca5VY07dBhAe8QfR/FSRY=");
    workflow.__set__("readySign", true);
    workflow.__set__("TOKENS_PER_REQUEST", 3); // limit the # of tokens for tests
});

/**
* Tests
*/
describe("signing request is cancelled", () => {
    test("signing off", () => {
        workflow.__set__("DO_SIGN", false);
        let b = beforeRequest(details, url);
        expect(b).toBeFalsy();
    });
    test("signing not activated", () => {
        workflow.__set__("readySign", false);
        let b = beforeRequest(details, url);
        expect(b).toBeFalsy();
    });
    test("url is not captcha request", () => {
        let b = beforeRequest(details, url);
        expect(b).toBeFalsy();
    });
    test("variables are reset", () => {
        setSpentHosts(url.host, true);
        setTimeSinceLastResp(0);
        let b = beforeRequest(details, url);
        expect(getSpentHosts(url.host)).toBeFalsy();
        expect(b).toBeFalsy();
    });
    test("already processed", () => {
        let newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX + CAPTCHA_BYPASS_SUFFIX);
        let b = beforeRequest(details, newUrl);
        expect(b).toBeFalsy();
    });
    test("already sent", () => {
        let newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
        setSpentHosts(newUrl.host, true);
        let b = beforeRequest(details, url);
        expect(b).toBeFalsy();
    });
});

describe("test XHR request", () => {
    const TOKEN_COUNT_STR = "bypass-tokens-count-1";
    
    test("incorrect config id", () => {
        function tryRun() {
            workflow.__set__("CONFIG_ID", 3);
            beforeRequest(details, newUrl);
        }
        let newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
        expect(tryRun).toThrowError("Incorrect config ID");
    });

    test("test that true is returned", () => {
        let newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
        let b = beforeRequest(details, newUrl);
        expect(b).toBeTruthy();
    });

    test("invalid signature response format does not sign", () => {
        setTimeSinceLastResp(0); // reset the variables
        workflow.__set__("SIGN_RESPONSE_FMT", "bad_fmt");
        _xhr = mockXHRGood;
        setXHR(_xhr);
        let newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
        let b = beforeRequest(details, newUrl);
        expect(b).toBeTruthy();
        let xhr = b.xhr;
        expect(xhr.onreadystatechange).toThrowError("invalid signature response format");
        expect(xhr.body).toContain("blinded-tokens=");
        expect(updateIconMock).toBeCalledTimes(2);
        expect(updateBrowserTabMock).not.toBeCalled();
    });

    test("bad status does not sign", () => {
        setTimeSinceLastResp(0); // reset the variables
        _xhr = mockXHRBadStatus;
        setXHR(_xhr);
        let newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
        let b = beforeRequest(details, newUrl);
        expect(b).toBeTruthy();
        let xhr = b.xhr;
        xhr.onreadystatechange();
        expect(xhr.body).toContain("blinded-tokens=");
        expect(updateIconMock).toBeCalledTimes(2);
        expect(updateBrowserTabMock).not.toBeCalled();
    });

    test("bad readyState does not sign", () => {
        setTimeSinceLastResp(0); // reset the variables
        _xhr = mockXHRBadReadyState;
        setXHR(_xhr);
        let newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
        let b = beforeRequest(details, newUrl);
        expect(b).toBeTruthy();
        let xhr = b.xhr;
        xhr.onreadystatechange();
        expect(updateIconMock).toBeCalledTimes(2);
        expect(updateBrowserTabMock).not.toBeCalled();
    });

    test("too many tokens does not sign", () => {
        function run() { 
            let b = beforeRequest(details, newUrl); 
            let xhr = b.xhr;
            xhr.onreadystatechange();
        };
        setTimeSinceLastResp(0); // reset the variables
        setMock(TOKEN_COUNT_STR, 400);
        let newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
        expect(run).toThrowError("upper bound");
        expect(updateIconMock).toBeCalledTimes(3);
        expect(updateBrowserTabMock).not.toBeCalled();
    });

    test("test store tokens", () => {
        let before;
        let after;
        function run() { 
            let tokens = [];
            for (let i=0; i<testTokens.length; i++) {
                tokens[i] = { token: testTokens[i].token, point: sec1DecodePointFromBytes(testTokens[i].point), blind: getBigNumFromBytes(testTokens[i].blind) };
            }
            const request = BuildIssueRequest(tokens);
            const xhrInfo = {newUrl: newUrl, requestBody: "blinded-tokens=" + request, tokens: tokens}
            let xhr = sendXhrSignReq(xhrInfo, newUrl, details.tabId); 
            xhr.responseText = respText;
            before = getMock(TOKEN_COUNT_STR);
            xhr.onreadystatechange();
            after = getMock(TOKEN_COUNT_STR);
        };
        setTimeSinceLastResp(0); // reset the variables
        setMock(TOKEN_COUNT_STR, 0);
        let newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
        expect(run).not.toThrow();
        expect(updateIconMock).toBeCalledTimes(4);
        expect(updateBrowserTabMock).toBeCalled();
        expect(after == before+3).toBeTruthy();
        expect(getSpendFlag(newUrl.host)).toBeTruthy();
    });

    test("test store tokens for captcha.website", () => {
        let before;
        let after;
        function run() { 
            let tokens = [];
            for (let i=0; i<testTokens.length; i++) {
                tokens[i] = { token: testTokens[i].token, point: sec1DecodePointFromBytes(testTokens[i].point), blind: getBigNumFromBytes(testTokens[i].blind) };
            }
            const request = BuildIssueRequest(tokens);
            const xhrInfo = {newUrl: newUrl, requestBody: "blinded-tokens=" + request, tokens: tokens}
            let xhr = sendXhrSignReq(xhrInfo, newUrl, details.tabId); 
            xhr.responseText = respText;
            before = getMock(TOKEN_COUNT_STR);
            xhr.onreadystatechange();
            after = getMock(TOKEN_COUNT_STR);
        };
        setTimeSinceLastResp(0); // reset the variables
        setMock(TOKEN_COUNT_STR, 0);
        let newUrl = new URL(CAPTCHA_HREF + EXAMPLE_SUFFIX);
        expect(run).not.toThrow();
        expect(updateIconMock).toBeCalledTimes(4);
        expect(updateBrowserTabMock).not.toBeCalled();
        expect(after == before+3).toBeTruthy();
        expect(getSpendFlag(newUrl.host)).toBeFalsy();
    });

    test("reloading off after sign", () => {
        let before;
        let after;
        function run() { 
            let tokens = [];
            for (let i=0; i<testTokens.length; i++) {
                tokens[i] = { token: testTokens[i].token, point: sec1DecodePointFromBytes(testTokens[i].point), blind: getBigNumFromBytes(testTokens[i].blind) };
            }
            const request = BuildIssueRequest(tokens);
            const xhrInfo = {newUrl: newUrl, requestBody: "blinded-tokens=" + request, tokens: tokens}
            let xhr = sendXhrSignReq(xhrInfo, newUrl, details.tabId); 
            xhr.responseText = respText;
            before = getMock(TOKEN_COUNT_STR);
            xhr.onreadystatechange();
            after = getMock(TOKEN_COUNT_STR);
        };
        setTimeSinceLastResp(0); // reset the variables
        setMock(TOKEN_COUNT_STR, 0);
        workflow.__set__("RELOAD_ON_SIGN", false);
        let newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
        expect(run).not.toThrow();
        expect(updateIconMock).toBeCalledTimes(4);
        expect(updateBrowserTabMock).not.toBeCalled();
        expect(after == before+3).toBeTruthy();
        expect(getSpendFlag(newUrl.host)).toBeFalsy();
    });

    describe("test parsing errors", () => {
        test("badly formatted response text", () => {
            function run() { 
                let b = beforeRequest(details, newUrl); 
                let xhr = b.xhr;
                xhr.responseText = "some bad data that should not be parsed.";
                xhr.onreadystatechange();
            };
            setTimeSinceLastResp(0); // reset the variables
            setMock(TOKEN_COUNT_STR, 0);
            let newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
            expect(run).toThrowError("signature response invalid");
            expect(updateIconMock).toBeCalledTimes(2);
            expect(updateBrowserTabMock).not.toBeCalled();
        });
        
        test("cannot decode point", () => {
            function run() { 
                let b = beforeRequest(details, newUrl); 
                let xhr = b.xhr;
                xhr.responseText = "signatures=WyJiYWRfcG9pbnQxIiwgImJhZF9wb2ludDIiXQ==";
                xhr.onreadystatechange();
            };
            setTimeSinceLastResp(0); // reset the variables
            setMock(TOKEN_COUNT_STR, 0);
            let newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
            expect(run).toThrow();
            expect(updateIconMock).toBeCalledTimes(2);
            expect(updateBrowserTabMock).not.toBeCalled();
        });

        describe("DLEQ formatting errors", () => {
            test("proof is not JSON", () => {
                function run() { 
                    let b = beforeRequest(details, newUrl); 
                    let xhr = b.xhr;
                    xhr.responseText = "signatures=WyJCTGZQdW9FdGxueHNic0p5dE5uUHg3Yk45N2l0KzQvd0dRVVVDWG1OM1lUcC9OOUpmMk9tWjk0TkM0WDBCbFJSTUltRUNLdUMrUlVXMm1wZlc4b1JxZG89IiwiQk5rSnBybVpVK3N1QngrWDY2Q3BEZyt4QkJlK0MzT1Z2K0U4VWhuelg0dG9ZOWgxYUo1ZUhvSmQvNHE1MjRTRUwrMHlPUjk1b2xaKzNWUVJ3ZUxqcjNzPSIsIkJOdHBFeEY4OHJTb0lwNjMvam9oMGJ0UWgyMFgwYk1TQnZMR1pCVFdKS3VzbDBZSHBzZ3FJbkNwcEpEUTJYb2xqQXV5Z250ZUh6MnR3S0lER3A2UExnND0iLCJiYWRfcHJvb2YiXQ==";
                    xhr.onreadystatechange();
                };
                setTimeSinceLastResp(0); // reset the variables
                setMock(TOKEN_COUNT_STR, 0);
                let newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                expect(run).toThrow();
                expect(updateIconMock).toBeCalledTimes(2);
                expect(updateBrowserTabMock).not.toBeCalled();
            });

            test("proof has bad points", () => {
                function run() { 
                    let b = beforeRequest(details, newUrl); 
                    let xhr = b.xhr;
                    xhr.responseText = "signatures=WyJCTGZQdW9FdGxueHNic0p5dE5uUHg3Yk45N2l0KzQvd0dRVVVDWG1OM1lUcC9OOUpmMk9tWjk0TkM0WDBCbFJSTUltRUNLdUMrUlVXMm1wZlc4b1JxZG89IiwiQk5rSnBybVpVK3N1QngrWDY2Q3BEZyt4QkJlK0MzT1Z2K0U4VWhuelg0dG9ZOWgxYUo1ZUhvSmQvNHE1MjRTRUwrMHlPUjk1b2xaKzNWUVJ3ZUxqcjNzPSIsIkJOdHBFeEY4OHJTb0lwNjMvam9oMGJ0UWgyMFgwYk1TQnZMR1pCVFdKS3VzbDBZSHBzZ3FJbkNwcEpEUTJYb2xqQXV5Z250ZUh6MnR3S0lER3A2UExnND0iLCJleUpRSWpvZ0ltVjVTbE5KYW05blNXeHNkRkp0ZEZsTlZYQnRXa2N4UjJNeVVsaFdWREJwVEVOQmFWRjVTVFpKUTBwYVlsVmFjbGRFUWs5YWJWSjBVbTVPYTFZeFZUbEpiakE5SW4wPSJd";
                    xhr.onreadystatechange();
                };
                setTimeSinceLastResp(0); // reset the variables
                setMock(TOKEN_COUNT_STR, 0);
                let newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                expect(run).toThrow();
                expect(updateIconMock).toBeCalledTimes(2);
                expect(updateBrowserTabMock).not.toBeCalled();
            });

            test("proof should not verify (bad lengths)", () => {
                function run() { 
                    let b = beforeRequest(details, newUrl); 
                    let xhr = b.xhr;
                    xhr.responseText = respBadProof;
                    xhr.onreadystatechange();
                };
                setTimeSinceLastResp(0); // reset the variables
                setMock(TOKEN_COUNT_STR, 0);
                workflow.__set__("TOKENS_PER_REQUEST", 4);
                let newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                expect(run).toThrowError("Unable to verify DLEQ");
                expect(run).not.toThrowError(workflow.__get__("DIGEST_INEQUALITY_ERR"));
                expect(updateIconMock).toBeCalledTimes(2);
                expect(updateBrowserTabMock).not.toBeCalled();
            });

            test("proof should not verify", () => {
                function run() { 
                    let b = beforeRequest(details, newUrl); 
                    let xhr = b.xhr;
                    xhr.responseText = respBadProof;
                    xhr.onreadystatechange();
                };
                let consoleNew = {
                    error: jest.fn()
                }
                workflow.__set__("console", consoleNew); // fake the console to check logs
                setTimeSinceLastResp(0); // reset the variables
                setMock(TOKEN_COUNT_STR, 0);
                let newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                expect(run).toThrowError("Unable to verify DLEQ");
                expect(consoleNew.error).toHaveBeenCalledWith(workflow.__get__("DIGEST_INEQUALITY_ERR"));
                expect(updateIconMock).toBeCalledTimes(2);
                expect(updateBrowserTabMock).not.toBeCalled();
            });
        });
    });
});

function getSpentHosts(key) {
    let spentHosts = workflow.__get__("spentHosts", spentHosts);
    return spentHosts[key];
}
function setSpentHosts(key, value) {
    let spentHosts = new Map();
    spentHosts[key] = value;
    workflow.__set__("spentHosts", spentHosts);
}
function setTimeSinceLastResp(value) {
    workflow.__set__("timeSinceLastResp", value);
}
function setMockFunctions() {
    workflow.__set__("atob", atob);
    workflow.__set__("btoa", btoa);
    workflow.__set__("get", getMock);
    workflow.__set__("set", setMock);
    workflow.__set__("updateIcon", updateIconMock);
    workflow.__set__("updateBrowserTab", updateBrowserTabMock);
    workflow.__set__("setSpendFlag", setSpendFlag);
    workflow.__set__("createShake256", createShake256);
    workflow.__set__("TOKENS_PER_REQUEST", 3);
}
function setXHR(xhr) {
    workflow.__set__("XMLHttpRequest", xhr);
}