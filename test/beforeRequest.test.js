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
const LISTENER_URLS = workflow.__get__("LISTENER_URLS");
const EXAMPLE_HREF = "https://example.com";
const CAPTCHA_HREF = "https://captcha.website";
const EXAMPLE_SUFFIX = "/cdn-cgi/l/chk_captcha?id=4716480f5bb534e8&g-recaptcha-response=03AMGVjXh24S6n8-HMQadfr8AmSr-2i87s1TTWUrhfnrIcti9hw1DigphUtiZzhU5R44VlJ3CmoH1W6wZaqde7iJads2bFaErY2bok29QfgZrbhO8q6UBbwLMkVlZ803M1UyDYhA9xYJqLR4kVtKhrHkDsUEKN4vXKc3CNxQpysmvdTqdt31Lz088ptkkksGLzRluDu-Np11ER6NX8XaH2S4iwIR823r3txm4eaMoEeoLfOD5S_6WHD5RhH0B7LRa_l7Vp5ksEB-0vyHQPLQQLOYixrC_peP3dG3dnaTY5UcUAUxZK4E74glzCu2PyRpKNnQ9akFz-niWiFCY0z-cuJeOArMvGOQCC9Q";
const CAPTCHA_BYPASS_SUFFIX = "&captcha-bypass=true";
const beforeRequest = workflow.__get__("beforeRequest");
const sendXhrSignReq = workflow.__get__("sendXhrSignReq");
const getBigNumFromBytes = workflow.__get__("getBigNumFromBytes");
const sec1DecodePointFromBytes = workflow.__get__("sec1DecodePointFromBytes");
const createVerificationXHR = workflow.__get__("createVerificationXHR");
const retrieveCommitments = workflow.__get__("retrieveCommitments");
const validateResponse = workflow.__get__("validateResponse");
const validateAndStoreTokens = workflow.__get__("validateAndStoreTokens");
const parseIssueResp = workflow.__get__("parseIssueResp");
const parseSigString = workflow.__get__("parseSigString");
const setConfig = workflow.__get__("setConfig");
const getCachedCommitments = workflow.__get__("getCachedCommitments");
const cacheCommitments = workflow.__get__("cacheCommitments");
const _scalarMult = workflow.__get__("_scalarMult");
const sec1EncodePoint = workflow.__get__("sec1EncodePoint");
let details;
let url;
const goodResponses = [
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
];

const PPConfigs = workflow.__get__("PPConfigs")

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
        expect(hkdfG == commitments.G).toBeTruthy();
        expect(hkdfH == commitments.H).toBeTruthy();
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
            expect(tryRun).toThrowError("Cannot read property 'var-reset'");
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
            expect(out.signatures[0] == "sig1").toBeTruthy();
            expect(out.signatures[2] == "sig3").toBeTruthy();
            expect(out.proof == "proof").toBeTruthy();
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
            expect(out.proof == "proof").toBeTruthy();
            expect(out.prng === "hkdf");
            expect(out.version).toBeTruthy();
        });
    });

    describe("test validation and storage", () => {
        let consoleMock;
        beforeAll(() => {
            setXHR(mockXHRCommitments, workflow);
            consoleMock = {
                warn: jest.fn(),
                error: jest.fn(),
            };
            workflow.__set__("console", consoleMock);
        });
        goodResponses.forEach((element) => {
            let commVersion;
            let testTokenData;
            let G;
            let H;
            beforeEach(() => {
                if (element.name == "hkdf") {
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
                    before = getMock(TOKEN_COUNT_STR);
                    xhr.onreadystatechange();
                    after = getMock(TOKEN_COUNT_STR);
                    version = out.version;
                }
                setTimeSinceLastResp(0); // reset the variables
                setMock(TOKEN_COUNT_STR, 0);
                const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                expect(consoleMock.error).not.toBeCalled();
                expect(run).not.toThrow();
                expect(updateIconMock).toBeCalledTimes(3);
                expect(updateBrowserTabMock).toBeCalled();
                expect(after == before+testTokenData.length).toBeTruthy();
                expect(getSpendFlag(newUrl.host)).toBeTruthy();
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
                    before = getMock(TOKEN_COUNT_STR);
                    const xhr = validateAndStoreTokens(newUrl, details.tabId, tokens, out);
                    expect(xhr).toBeFalsy(); // because the commitments are cached, the xhr should not be generated.
                    after = getMock(TOKEN_COUNT_STR);
                    version = out.version;
                }
                setTimeSinceLastResp(0); // reset the variables
                setMock(TOKEN_COUNT_STR, 0);
                const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                expect(consoleMock.error).not.toBeCalled();
                expect(run).not.toThrow();
                expect(updateIconMock).toBeCalledTimes(3);
                expect(updateBrowserTabMock).toBeCalled();
                expect(after == before+testTokenData.length).toBeTruthy();
                expect(getSpendFlag(newUrl.host)).toBeTruthy();
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
                localStorage[CACHED_COMMITMENTS_STRING] = JSON.stringify(commStruct);
                function run() {
                    const tokens = [];
                    for (let i=0; i<testTokenData.length; i++) {
                        tokens[i] = {token: testTokenData[i].data, point: sec1DecodePointFromBytes(testTokenData[i].point), blind: getBigNumFromBytes(testTokenData[i].blind)};
                    }
                    const out = parseRespString(element.string);
                    before = getMock(TOKEN_COUNT_STR);
                    const xhr = validateAndStoreTokens(newUrl, details.tabId, tokens, out);
                    expect(xhr).toBeTruthy();
                    expect(xhr.send).toBeCalledTimes(1);
                    before = getMock(TOKEN_COUNT_STR);
                    xhr.onreadystatechange();
                    after = getMock(TOKEN_COUNT_STR);
                    version = out.version;
                }
                setTimeSinceLastResp(0); // reset the variables
                setMock(TOKEN_COUNT_STR, 0);
                const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                expect(consoleMock.error).not.toBeCalled();
                expect(run).not.toThrow();
                expect(consoleMock.warn).toBeCalled();
                expect(updateIconMock).toBeCalledTimes(3);
                expect(updateBrowserTabMock).toBeCalled();
                expect(after == before+testTokenData.length).toBeTruthy();
                expect(getSpendFlag(newUrl.host)).toBeTruthy();
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
                    before = getMock(TOKEN_COUNT_STR);
                    xhr.onreadystatechange();
                    after = getMock(TOKEN_COUNT_STR);
                    version = out.version;
                }
                setTimeSinceLastResp(0); // reset the variables
                setMock(TOKEN_COUNT_STR, 0);
                const newUrl = new URL(CAPTCHA_HREF + EXAMPLE_SUFFIX);
                expect(consoleMock.error).not.toBeCalled();
                expect(run).not.toThrow();
                expect(updateIconMock).toBeCalledTimes(3);
                expect(updateBrowserTabMock).not.toBeCalled();
                expect(after == before+testTokenData.length).toBeTruthy();
                expect(getSpendFlag(newUrl.host)).toBeFalsy();
                const cache = getCachedCommitments(version);
                expect(cache.G === G).toBeTruthy();
                expect(cache.H === H).toBeTruthy();
            });

            test(`reloading off after sign: ${element.name}`, () => {
                let before;
                let after;
                function run() {
                    const tokens = [];
                    for (let i=0; i<testTokenData.length; i++) {
                        tokens[i] = {data: testTokenData[i].data, point: sec1DecodePointFromBytes(testTokenData[i].point), blind: getBigNumFromBytes(testTokenData[i].blind)};
                    }
                    const out = parseRespString(element.string);
                    const xhr = validateAndStoreTokens(newUrl, details.tabId, tokens, out);
                    before = getMock(TOKEN_COUNT_STR);
                    xhr.onreadystatechange();
                    after = getMock(TOKEN_COUNT_STR);
                }
                setTimeSinceLastResp(0); // reset the variables
                setMock(TOKEN_COUNT_STR, 0);
                workflow.__set__("RELOAD_ON_SIGN", false);
                const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                expect(consoleMock.error).not.toBeCalled();
                expect(run).not.toThrow();
                expect(updateIconMock).toBeCalledTimes(3);
                expect(updateBrowserTabMock).not.toBeCalled();
                expect(after == before+testTokenData.length).toBeTruthy();
                expect(getSpendFlag(newUrl.host)).toBeFalsy();
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
