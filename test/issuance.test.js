/**
* Integrations tests for when headers are sent by the browser
*
* @author: Alex Davidson
*/
import btoa from "btoa";
import atob from "atob";
import createShake256 from "../src/crypto/keccak/keccak.js";

import rewire from "rewire";
const workflow = rewire("../addon/compiled/test_compiled.js");
const URL = window.URL;
const sjcl = workflow.__get__("sjcl");

/**
* Functions/variables
*/
const TOKEN_COUNT_STR = "bypass-tokens-count-1";
const EXAMPLE_HREF = "https://example.com";
const CAPTCHA_HREF = "https://captcha.website";
const EXAMPLE_SUFFIX = "/cdn-cgi/l/chk_captcha?id=4716480f5bb534e8&g-recaptcha-response=03AMGVjXh24S6n8-HMQadfr8AmSr-2i87s1TTWUrhfnrIcti9hw1DigphUtiZzhU5R44VlJ3CmoH1W6wZaqde7iJads2bFaErY2bok29QfgZrbhO8q6UBbwLMkVlZ803M1UyDYhA9xYJqLR4kVtKhrHkDsUEKN4vXKc3CNxQpysmvdTqdt31Lz088ptkkksGLzRluDu-Np11ER6NX8XaH2S4iwIR823r3txm4eaMoEeoLfOD5S_6WHD5RhH0B7LRa_l7Vp5ksEB-0vyHQPLQQLOYixrC_peP3dG3dnaTY5UcUAUxZK4E74glzCu2PyRpKNnQ9akFz-niWiFCY0z-cuJeOArMvGOQCC9Q";
const CAPTCHA_BYPASS_SUFFIX = "&captcha-bypass=true";
const CACHED_COMMITMENTS_STRING = "cached-commitments";
const beforeRequest = workflow.__get__("beforeRequest");
const sendXhrSignReq = workflow.__get__("sendXhrSignReq");
const getBigNumFromBytes = workflow.__get__("getBigNumFromBytes");
const sec1DecodePointFromBytes = workflow.__get__("sec1DecodePointFromBytes");
const decompressPoint = workflow.__get__("decompressPoint");
const createVerificationXHR = workflow.__get__("createVerificationXHR");
const retrieveCommitments = workflow.__get__("retrieveCommitments");
const validateResponse = workflow.__get__("validateResponse");
const validateAndStoreTokens = workflow.__get__("validateAndStoreTokens");
const parseIssueResp = workflow.__get__("parseIssueResp");
const parseSigString = workflow.__get__("parseSigString");
const setConfig = workflow.__get__("setConfig");
const getCachedCommitments = workflow.__get__("getCachedCommitments");
const cacheCommitments = workflow.__get__("cacheCommitments");
let localStorage;
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
    {
        string: `signatures=eyJzaWdzIjpbIkF6cTF6TGFRMkVUY3Q0Q3kyZVdSSnRZcnlGTzZBYkxET2JvY0czakFQa3RxIiwiQTJSK0dyZVVheERCd2NrdDB6UGkvSjZUNkYvZTlaT2I4dk4ycm9XU1NGRSsiXSwicHJvb2YiOiJZbUYwWTJndGNISnZiMlk5ZXlKUUlqb2laWGxLUkVscWIybFVSR3d3WTJwS2ExVnRlRTFaYlRWMVZGVjRhV0ZHU2xGbFZ6QjNUVzA1VldGWE9WWlRiVkpwVjBaV2FGTXdZM1pSYTF
            aUlRUQjBWMUpVTUdsTVEwcFRTV3B2YVUxVlNuWlZWR1J6WkRCa1VtRnFSbTFVUjNSU1MzcHNNVm96YjNwVVJXUnlZbGM1YzFsdWJERmlSMVpYVGtoS1ZXVnFUbFJsYkVKSFZGUXdhV1pSUFQwaWZRPT0iLCJ2ZXJzaW9uIjoiaGtkZiIsInBybmciOiJoa2RmIn0=`,
        name: "compressed-hkdf",
    },
];
const respBadProof = `signatures=WyJCQVRkL01qTnNuTTZxaHBQZzFLS216RnVHOUNQRzdFbERVSU5EVjFJQmd5WTN2RkVrdENUMk8ybW82dGNNLy9qMWE2Zkoyb1dMb2Z5MGZqYWVjTlBEeWM9IiwiQk9aQnY4dnNxdFg3VzRKcFlSZERHMm5QSEtHTDBMVUtFY1VCY1ZTZjcrcnlxRHRRdC9WZFFlZHRLMkVNa1AvMXZvcjl6dkkvRDZ0ekNZQi9CQkRLRkpRPSIsIkJNMW9UdW9Bc3RiTzQvN3ZIcUEwaDhNbG5
rNG5UdEJ6NzdvN25RWitqM2RhQ09FU3RXM1VTWHRKdGdmcnVramZBNkxDUksyUmpFVGZVUWU1cmhpaEY0ND0iLCJZbUYwWTJndGNISnZiMlk5ZXlKRElqcGJJbXhrWldacVJ6QXZaRXh2VUhVdkt6UjNURkl5TTJaM2JsWllWVGQwY1dSYU5uSmhlbWhqYTNSa1JYYzlJaXdpZWt4M2QyZHROVGxaU0c5T2FtRkVhVkJ5UzBSd1VrOU5ZMnBsTlhwc2IxaEtXa2MyY1ZJMGJUQXhRVDBpTENKbl
IzTnBTRE5XYkRGRVMwVjFaMjl1VVRoRmVFODVaRkkxU0Voc05HUTBNMmRGUWpWd04wUkRhV3BSUFNKZExDSk5JanBiSWtKSU5VSndZVkpUZEdwWkwwMXNNMVVyUW5aREwzUjNaRzVpVldzMVdFZG9Nbk5rZUZOV09HWkJkR2cyWXpKaFlreHhZV1o2Y2pKcEsySm5kVTVpS3l0Mk0xaEVOV3RHTWt0V2JFaGtSamxzYTNwNmRtVTVhejBpTENKQ1RIWTFZM2hwVlZscVRWbEdiMHczY1VGWmVTO
TBiSGRsUmtGeGRrWlBiVEZQWVZFeFVIVnJaRUZYWTB0NFpqZEpaekZWU0VoR05saENOMWxuVVd0dVFrOTVkSHBwYTNsUGFFZHpUbmcyYjFoMFZHbGFVRms5SWl3aVFsQTVLMkZUWlZKbU9XbDZNRGsyWm5Gb1NreHNTMFIwYjFORVRTdDFVVUpOVVVobGJHVktia1prZUdzMWRURnViRlF2VDFrNVZsaEdSM0JvYWxWSGJGSkllRW92UTJoaVZrdDNSVGwxZG1KSmJYWnhjWGxSUFNKZExDSlFJ
am9pWlhsS1NFbHFiMmxSYXpsd1drVldNVlI2YkVsVk1IQjZWRlp3V2xKVE9WRmFiVTB4VWtOemQxSlZlSFZOUjBwNFlVZHdSbHBYV1hsVWVrSXhTekIwUW1SNlRtMVZSVEZKVTBab01GWnRlRVpSYmxwYVlXdFZNVk5UT1ZCVWJWazFWVE5zVlZKc1RuSlRSRTUwVkVVMVNXRXhUWGRPYTFJeFRtMW9VbEJUU1hOSmF6QnBUMmxLUTFGV1drOWlhMmhQWTI1c1NWcFlRbnBPUmtKNlZsZFdTMUp
xYTNkWlZGSldWbXhyZWxkclVqTlNWa0pRV2tWck5WRnROV3hoZW1oRVUwYzVXRkp0VlhaWGJUbFNUMWRrY0ZadFJuSlVSa0o1VjBoQmVVNUdRbEZqUlVwSVVXeGtiV0pGV25aVE1IQnFWa2RrVTFWdFJYSk5SVlU1U1dsM2FWTkRTVFpKYTBwSlZERkNUMUZXWkZsVmJXc3dZMms1VDFKWVFqQlVNbXhOVkROQk5GUldUak5aTVdkM1pHdG9lVlpyVWxOWFNGbDRUbXR3ZFdJelpHcE5WMVpaVj
BjNE1XVkZXa2RUTUd4UVUxUmFkRlpZUVRSaGVtdDJXbGRPYUU1V1dscE5SR1JyVVcxb1FscFVhRkphYkVsMlVteE9VMWRVTUdsTVEwcGhTV3B2YVZGclJrbE9SMVY2WlZkU05WRlhXbXBVYm1jMVlYcGplVlJJU2tKaVJ6bGFWREJHYVdGc1RsQlNSM2Q0V2pGU1ZHRnFXbXRqTVVGNVN6TkNOVkpZVWxGWFJHd3pWWHBPU1ZSNlVrNU5iazVNWkZkT01GTXdSazFUTW14MllVaHdlRTR5V1RGa
mFrcFhVekJKTUU5SVJraE5SR3hXVUZOSmMwbHNTV2xQYVVwTVlVWk9WMVpYY0V0aVZHaFlZMFJDTUU5RVRuRk9NRlpTV1hwa00xSkZhekZYYkU1NFRWUkNVRTlIWkROVlJHYzBaRE5XVTFwWVFuSlFVMGx6U1d0TmFVOXBTa2xXUjFaTFZWVTVOVkZVVWxaV2F6RlRVbFJXVmxkRldqWlhiRWt5Wkd4d1RsSkZkSHBsYVhSelYwVXhkMk5IZERGYVJGWlBVbGhPVGxCVFNqa2lMQ0phSWpwYklr
SkJTemhFUVU1bU9HRldjSEZtVVZoS1J5dFZkQzlJWVZOeU5XWmpaVnB1WlVkbmNFMXRaR0ZLUTNNeVUya3dVbWRaVm5sNWNERlVUU3RwTTBaa01VRkhWMmgyYVdKNFRYcG9SbVY1WTFOc0swSXZkMmR2YXowaUxDSkNSMWc0YjFFeVpGRkpjV1ZLZEZwMGNtOWthM1E1YlhKdFJtaEJiVWRWVUZsbGVWVTNVRGRqWlRsVWRURm9LM0F3Vm1oTFZXbFpVek13WkVRclVua3JjVVZSYm05VE5FSjZ
jRmhpUmxoUFkzQnhhM0JIVjJjOUlpd2lRa2RzUWpWak4yaFBaWE5GZEU5U2VYRldiREZHVFRkR1ozcHZNR3QzVlhwQ2FYRnNhVkZSVEVScVN6TnhiRGw0UWxaaFJrZHRhREIwVVdSYWNsTnJXR3A0VTB4dWVVZHNiRk5wT0ZwWVJYazROMjFOVDBGRlBTSmRmUT09Il0=`;
const respBadJson = "signatures=WyJCTGZQdW9FdGxueHNic0p5dE5uUHg3Yk45N2l0KzQvd0dRVVVDWG1OM1lUcC9OOUpmMk9tWjk0TkM0WDBCbFJSTUltRUNLdUMrUlVXMm1wZlc4b1JxZG89IiwiQk5rSnBybVpVK3N1QngrWDY2Q3BEZyt4QkJlK0MzT1Z2K0U4VWhuelg0dG9ZOWgxYUo1ZUhvSmQvNHE1MjRTRUwrMHlPUjk1b2xaKzNWUVJ3ZUxqcjNzPSIsIkJOdHBFeEY4OHJTb0lwNjMvam9oMGJ0UWgyMFgwYk1TQnZMR1pCVFdKS3VzbDBZSHBzZ3FJbkNwcEpEUTJYb2xqQXV5Z250ZUh6MnR3S0lER3A2UExnND0iLCJiYWRfcHJvb2YiXQ==";
const respBadPoints = "signatures=WyJCTGZQdW9FdGxueHNic0p5dE5uUHg3Yk45N2l0KzQvd0dRVVVDWG1OM1lUcC9OOUpmMk9tWjk0TkM0WDBCbFJSTUltRUNLdUMrUlVXMm1wZlc4b1JxZG89IiwiQk5rSnBybVpVK3N1QngrWDY2Q3BEZyt4QkJlK0MzT1Z2K0U4VWhuelg0dG9ZOWgxYUo1ZUhvSmQvNHE1MjRTRUwrMHlPUjk1b2xaKzNWUVJ3ZUxqcjNzPSIsIkJOdHBFeEY4OHJTb0lwNjMvam9oMGJ0UWgyMFgwYk1TQnZMR1pCVFdKS3VzbDBZSHBzZ3FJbkNwcEpEUTJYb2xqQXV5Z250ZUh6MnR3S0lER3A2UExnND0iLCJleUpRSWpvZ0ltVjVTbE5KYW05blNXeHNkRkp0ZEZsTlZYQnRXa2N4UjJNeVVsaFdWREJwVEVOQmFWRjVTVFpKUTBwYVlsVmFjbGRFUWs5YWJWSjBVbTVPYTFZeFZUbEpiakE5SW4wPSJd";
const testTokens = JSON.parse(`[{"data":[237,20,250,80,161,8,37,128,78,147,159,160,227,23,161,220,22,137,228,182,45,72,175,25,57,126,251,158,253,246,209,1],"point":[4,178,119,34,84,93,23,7,255,30,232,166,5,142,110,153,178,32,198,114,30,102,86,121,195,92,214,144,84,155,61,235,94,227,235,75,30,198,92,206,234,196,86,106,0,79,14,9,225,63,249,58,139,100,21,117,195,204,225,53,217,141,220,224,35],"blind":[73,107,72,26,128,56,94,59,31,54,94,206,126,83,177,12,153,141,232,123,254,182,63,221,56,148,42,62,220,173,4,134]},{"data":[254,122,184,29,171,157,229,38,101,187,66,154,255,160,164,128,17,142,250,241,176,89,123,12,53,24,236,91,58,3,212,217],"point":[4,237,62,141,228,215,60,240,129,29,36,33,222,205,76,22,88,238,41,234,39,29,92,3,210,140,190,200,19,7,124,159,211,84,135,68,248,26,255,98,27,27,64,190,169,189,78,27,215,84,16,210,253,206,22,194,168,165,138,228,13,211,203,173,131],"blind":[44,0,207,19,25,28,76,114,193,226,49,111,160,152,161,102,207,170,195,9,31,220,120,202,182,50,135,83,7,2,134,21]},{"data":[223,42,23,79,237,61,125,106,86,135,234,109,171,67,86,202,166,142,77,238,69,175,78,67,214,214,246,171,20,178,166,251],"point":[4,1,217,22,212,2,213,172,249,228,15,57,187,210,224,69,225,254,67,195,37,79,189,197,43,1,57,213,66,100,118,118,239,41,145,71,177,212,83,25,55,198,198,40,110,29,155,189,82,17,11,156,4,99,60,168,157,182,156,187,166,71,251,176,191],"blind":[74,150,233,91,28,35,116,26,6,87,77,9,8,200,166,69,152,61,192,210,236,207,68,138,250,104,16,195,92,232,43,132]}]`);
const testTokensBadLength = JSON.parse(`[{"data":[254,122,184,29,171,157,229,38,101,187,66,154,255,160,164,128,17,142,250,241,176,89,123,12,53,24,236,91,58,3,212,217],"point":[4,237,62,141,228,215,60,240,129,29,36,33,222,205,76,22,88,238,41,234,39,29,92,3,210,140,190,200,19,7,124,159,211,84,135,68,248,26,255,98,27,27,64,190,169,189,78,27,215,84,16,210,253,206,22,194,168,165,138,228,13,211,203,173,131],"blind":[44,0,207,19,25,28,76,114,193,226,49,111,160,152,161,102,207,170,195,9,31,220,120,202,182,50,135,83,7,2,134,21]},{"data":[223,42,23,79,237,61,125,106,86,135,234,109,171,67,86,202,166,142,77,238,69,175,78,67,214,214,246,171,20,178,166,251],"point":[4,1,217,22,212,2,213,172,249,228,15,57,187,210,224,69,225,254,67,195,37,79,189,197,43,1,57,213,66,100,118,118,239,41,145,71,177,212,83,25,55,198,198,40,110,29,155,189,82,17,11,156,4,99,60,168,157,182,156,187,166,71,251,176,191],"blind":[74,150,233,91,28,35,116,26,6,87,77,9,8,200,166,69,152,61,192,210,236,207,68,138,250,104,16,195,92,232,43,132]}]`);
const testG = "BOidEuO9HSJsMZYE/Pfc5D+0ELn0bqhjEef2O0u+KAw3fPMHHXtVlEBvYjE5I/ONf9SyTFSkH3mLNHkS06Du6hQ=";
const testH = "BHOPNAWXRi4r/NEptOiLOp8MSwcX0vHrVDRXv16Jnowc1eXXo5xFFKIOI6mUp8k9/eca5VY07dBhAe8QfR/FSRY=";
const testDevG = "BIpWWWWFtDRODAHEzZlvjKyDwQAdh72mYKMAsGrtwsG7XmMxsy89gfiOFbX3RZ9Ik6jEYWyJB0TmnWNVeeZBt5Y=";
const testDevH = "BKjGppSCZCsL08YlF4MJcml6YkCglMvr56WlUOFjn9hOKXNa0iB9t8OHXW7lARIfYO0CZE/t1SlPA1mXdi/Rcjo=";
// different test data for where HKDF is used for proof verification
const genBytes = [4, 107, 23, 209, 242, 225, 44, 66, 71, 248, 188, 230, 229, 99, 164, 64, 242, 119, 3, 125, 129, 45, 235, 51, 160, 244, 161, 57, 69, 216, 152, 194, 150, 79, 227, 66, 226, 254, 26, 127, 155, 142, 231, 235, 74, 124, 15, 158, 22, 43, 206, 51, 87, 107, 49, 94, 206, 203, 182, 64, 104, 55, 191, 81, 245];
const hBytes = [4, 97, 25, 196, 70, 213, 45, 33, 189, 8, 106, 8, 111, 95, 39, 119, 7, 91, 32, 101, 186, 169, 186, 87, 156, 1, 140, 185, 141, 106, 90, 5, 193, 178, 251, 89, 7, 236, 175, 62, 91, 196, 188, 86, 40, 203, 15, 230, 241, 15, 49, 65, 124, 16, 47, 188, 65, 97, 15, 118, 139, 47, 130, 143, 161];
const hkdfG = sjcl.codec.base64.fromBits(sjcl.codec.bytes.toBits(genBytes));
const hkdfH = sjcl.codec.base64.fromBits(sjcl.codec.bytes.toBits(hBytes));
// we only need token.point (so token.data and token.blind are mocked and do match the point data)
const testTokensHkdf = JSON.parse(`[{"data":[237,20,250,80,161,8,37,128,78,147,159,160,227,23,161,220,22,137,228,182,45,72,175,25,57,126,251,158,253,246,209,1],"point":[4,96,37,164,31,129,161,96,198,72,207,232,253,202,164,46,95,125,167,167,16,85,248,226,63,29,199,228,32,74,184,75,112,80,67,186,92,112,0,18,62,31,208,88,21,10,77,55,151,0,143,87,168,178,83,119,102,217,65,156,115,150,186,82,121],"blind":[73,107,72,26,128,56,94,59,31,54,94,206,126,83,177,12,153,141,232,123,254,182,63,221,56,148,42,62,220,173,4,134]},{"data":[237,20,250,80,161,8,37,128,78,147,159,160,227,23,161,220,22,137,228,182,45,72,175,25,57,126,251,158,253,246,209,1],"point":[4,226,239,220,115,116,126,21,227,139,122,27,185,15,229,228,239,150,75,59,141,204,253,164,40,248,90,67,20,32,200,78,252,160,47,15,9,200,58,130,65,180,69,114,160,89,171,73,192,128,163,157,11,206,45,93,11,68,255,93,1,43,81,132,231],"blind":[73,107,72,26,128,56,94,59,31,54,94,206,126,83,177,12,153,141,232,123,254,182,63,221,56,148,42,62,220,173,4,134]}]`);
const testTokensHkdfCompressed = JSON.parse(`[{"data":[237,20,250,80,161,8,37,128,78,147,159,160,227,23,161,220,22,137,228,182,45,72,175,25,57,126,251,158,253,246,209,1],"point":[3,96,37,164,31,129,161,96,198,72,207,232,253,202,164,46,95,125,167,167,16,85,248,226,63,29,199,228,32,74,184,75,112],"blind":[73,107,72,26,128,56,94,59,31,54,94,206,126,83,177,12,153,141,232,123,254,182,63,221,56,148,42,62,220,173,4,134]},{"data":[237,20,250,80,161,8,37,128,78,147,159,160,227,23,161,220,22,137,228,182,45,72,175,25,57,126,251,158,253,246,209,1],"point":[3,226,239,220,115,116,126,21,227,139,122,27,185,15,229,228,239,150,75,59,141,204,253,164,40,248,90,67,20,32,200,78,252],"blind":[73,107,72,26,128,56,94,59,31,54,94,206,126,83,177,12,153,141,232,123,254,182,63,221,56,148,42,62,220,173,4,134]}]`);

/* mock impls */
function getMock(key) {
    return localStorage[key];
}
function setMock(key, value) {
    localStorage[key] = value;
}
function clearCachedCommitmentsMock() {
    localStorage[CACHED_COMMITMENTS_STRING] = null;
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
    };
    _xhr.setRequestHeader = function(name, value) {
        _xhr.requestHeaders[name] = value;
    };
    _xhr.overrideMimeType = jest.fn();
    _xhr.body;
    _xhr.send = jest.fn();
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

function mockXHRCommitments() {
    mockXHR(this);
    this.status = 200;
    this.readyState = 4;
    this.responseText = `{"CF":{"dev":{"G": "${testDevG}","H": "${testDevH}"},"1.0":{"G":"${testG}","H":"${testH}"},"1.1":{"G":"new_11_commitment_g","H":"new_11_commitment_h"},"hkdf":{"G":"${hkdfG}","H":"${hkdfH}"}}}`;
}

let _xhr;

beforeEach(() => {
    const storedTokens = `[ { "data":[24,62,56,102,76,127,201,111,161,218,249,109,34,122,160,219,93,186,246,12,178,249,241,108,69,181,77,140,158,13,216,184],"point":"/MWxehOPdGROly7JRQxXp4G8WRzMHTqIjtc17kXrk6W4i2nIp3QRv3/1EVQAeJfmTvIwVUgJTMI3KhGQ4pSNTQ==","blind":"0x46af9794d53f040607a35ad297f92aef6a9879686279a12a0a478b2e0bde9089"},{"token":[131,120,153,53,158,58,11,155,160,109,247,176,176,153,14,161,150,120,43,180,188,37,35,75,52,219,177,16,24,101,241,159],"point":"sn4KWtjU+RL7aE53zp4wUdhok4UU9iZTAwQVVAmBoGA+XltG/E3V5xIKZ1fxDs0qhbFG1ujXajYUt831rQcCug==","blind":"0xd475b86c84c94586503f035911388dd702f056472a755e964cbbb3b58c76bd53" } ]`;
    localStorage = {
        "bypass-tokens-1": storedTokens,
        "bypass-tokens-count-1": 2,
    };
    details = {
        method: "GET",
        requestHeaders: [],
        requestId: "212",
        tabId: "101",
    };
    url = new URL(EXAMPLE_HREF);
    setMockFunctions();
    setTimeSinceLastResp(Date.now());
    setConfig(1); // set the CF config
    workflow.__set__("readySign", true);
    workflow.__set__("TOKENS_PER_REQUEST", 3); // limit the # of tokens for tests
});

/**
* Tests
*/
describe("commitments parsing and caching", () => {
    beforeEach(() => {
        workflow.__set__("XMLHttpRequest", mockXHRCommitments);
        setXHR(mockXHRCommitments);
    });

    test("parse correctly (null version)", () => {
        const xhr = createVerificationXHR(); // this usually takes params
        const commitments = retrieveCommitments(xhr);
        expect(testG == commitments.G).toBeTruthy();
        expect(testH == commitments.H).toBeTruthy();
    });

    test("parse correctly (v1.0)", () => {
        const xhr = createVerificationXHR(); // this usually takes params
        const commitments = retrieveCommitments(xhr, "1.0");
        expect(testG == commitments.G).toBeTruthy();
        expect(testH == commitments.H).toBeTruthy();
    });

    test("parse correctly (v1.1)", () => {
        const v11G = "new_11_commitment_g";
        const v11H = "new_11_commitment_h";
        const xhr = createVerificationXHR(); // this usually takes params
        const commitments = retrieveCommitments(xhr, "1.1");
        expect(v11G == commitments.G).toBeTruthy();
        expect(v11H == commitments.H).toBeTruthy();
    });

    test("parse correctly (dev)", () => {
        workflow.__set__("DEV", true);
        const xhr = createVerificationXHR(); // this usually takes params
        const commitments = retrieveCommitments(xhr, "1.1");
        expect(testDevG == commitments.G).toBeTruthy();
        expect(testDevH == commitments.H).toBeTruthy();
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

describe("signing request is cancelled", () => {
    test("signing off", () => {
        workflow.__set__("DO_SIGN", false);
        const b = beforeRequest(details, url);
        expect(b).toBeFalsy();
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
        setSpentHosts(url.host, true);
        setTimeSinceLastResp(0);
        const b = beforeRequest(details, url);
        expect(getSpentHosts(url.host)).toBeFalsy();
        expect(b).toBeFalsy();
    });
    test("already processed", () => {
        const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX + CAPTCHA_BYPASS_SUFFIX);
        const b = beforeRequest(details, newUrl);
        expect(b).toBeFalsy();
    });
    test("already sent", () => {
        const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
        setSpentHosts(newUrl.host, true);
        const b = beforeRequest(details, url);
        expect(b).toBeFalsy();
    });
});

describe("test sending sign requests", () => {
    const validateRespMock = jest.fn();
    workflow.__set__("validateResponse", validateRespMock);

    test("incorrect config id", () => {
        function tryRun() {
            workflow.__set__("CONFIG_ID", 3);
            beforeRequest(details, newUrl);
        }
        const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
        expect(tryRun).toThrowError("Incorrect config ID");
    });

    test("test that true is returned", () => {
        const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
        const b = beforeRequest(details, newUrl);
        expect(b).toBeTruthy();
        expect(b.xhr).toBeTruthy();
    });

    test("bad status does not sign", () => {
        setTimeSinceLastResp(0); // reset the variables
        _xhr = mockXHRBadStatus;
        setXHR(_xhr);
        const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
        const b = beforeRequest(details, newUrl);
        expect(b).toBeTruthy();
        const xhr = b.xhr;
        xhr.onreadystatechange();
        expect(validateRespMock).not.toBeCalled();
        expect(updateIconMock).toBeCalledTimes(2);
        expect(updateBrowserTabMock).not.toBeCalled();
    });

    test("bad readyState does not sign", () => {
        setTimeSinceLastResp(0); // reset the variables
        _xhr = mockXHRBadReadyState;
        setXHR(_xhr);
        const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
        const b = beforeRequest(details, newUrl);
        expect(b).toBeTruthy();
        const xhr = b.xhr;
        xhr.onreadystatechange();
        expect(validateRespMock).not.toBeCalled();
        expect(updateIconMock).toBeCalledTimes(2);
        expect(updateBrowserTabMock).not.toBeCalled();
    });

    test("too many tokens does not sign", () => {
        _xhr = mockXHRGood;
        setXHR(_xhr);
        function run() {
            const b = beforeRequest(details, newUrl);
            const xhr = b.xhr;
            xhr.onreadystatechange();
        }
        setTimeSinceLastResp(0); // reset the variables
        setMock(TOKEN_COUNT_STR, 400);
        const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
        expect(run).toThrowError("upper bound");
        expect(validateRespMock).not.toBeCalled();
        expect(updateIconMock).toBeCalledTimes(3);
        expect(updateBrowserTabMock).not.toBeCalled();
    });

    test("correct XHR response triggers validation", () => {
        _xhr = mockXHRGood;
        setXHR(_xhr);
        function run() {
            const request = "";
            const xhrInfo = {newUrl: newUrl, requestBody: "blinded-tokens=" + request, tokens: ""};
            const xhr = sendXhrSignReq(xhrInfo, newUrl, details.tabId);
            xhr.responseText = "";
            xhr.onreadystatechange();
        }
        setTimeSinceLastResp(0); // reset the variables
        setMock(TOKEN_COUNT_STR, 0);
        const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
        expect(run).not.toThrow();
        expect(validateRespMock).toBeCalled();
        expect(updateIconMock).toBeCalledTimes(2);
    });
});

describe("test validating response", () => {
    describe("test response format errors", () => {
        test("invalid signature response format does not sign", () => {
            function run() {
                setTimeSinceLastResp(0); // reset the variables
                workflow.__set__("SIGN_RESPONSE_FMT", "bad_fmt");
                const tabId = details.tabId;
                validateResponse(url, tabId, "", "");
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
            expect(out.signatures[0] == "sig1").toBeTruthy();
            expect(out.signatures[2] == "sig3").toBeTruthy();
            expect(out.proof == "proof").toBeTruthy();
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
            expect(out.signatures[0] == "sig1").toBeTruthy();
            expect(out.signatures[2] == "sig3").toBeTruthy();
            expect(out.proof == "proof").toBeTruthy();
            expect(out.prng === "hkdf");
            expect(out.version).toBeTruthy();
        });
    });

    describe("test validation and storage", () => {
        let consoleMock;
        beforeAll(() => {
            setXHR(mockXHRCommitments);
            consoleMock = {
                warn: jest.fn(),
                error: jest.fn(),
            };
            workflow.__set__("console", consoleMock);
        });
        goodResponses.forEach((element) => {
            let commVersion;
            let decodePoint;
            let testTokenData;
            let G;
            let H;
            beforeEach(() => {
                decodePoint = sec1DecodePointFromBytes;
                if (element.name.includes("hkdf")) {
                    commVersion = "hkdf";
                    if (element.name.includes("compressed")) {
                        testTokenData = testTokensHkdfCompressed;
                        decodePoint = decompressPoint;
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
                }
            });
            test(`test store tokens: ${element.name}`, () => {
                let before;
                let after;
                let version;
                function run() {
                    const tokens = [];
                    for (let i=0; i<testTokenData.length; i++) {
                        tokens[i] = {data: testTokenData[i].data, point: decodePoint(testTokenData[i].point), blind: getBigNumFromBytes(testTokenData[i].blind)};
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
                        tokens[i] = {token: testTokenData[i].data, point: decodePoint(testTokenData[i].point), blind: getBigNumFromBytes(testTokenData[i].blind)};
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
                        tokens[i] = {token: testTokenData[i].data, point: decodePoint(testTokenData[i].point), blind: getBigNumFromBytes(testTokenData[i].blind)};
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
                        tokens[i] = {data: testTokenData[i].data, point: decodePoint(testTokenData[i].point), blind: getBigNumFromBytes(testTokenData[i].blind)};
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
                        tokens[i] = {data: testTokenData[i].data, point: decodePoint(testTokenData[i].point), blind: getBigNumFromBytes(testTokenData[i].blind)};
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
                    for (let i=0; i<testTokens.length; i++) {
                        tokens[i] = {data: testTokens[i].data, point: sec1DecodePointFromBytes(testTokens[i].point), blind: getBigNumFromBytes(testTokens[i].blind)};
                    }
                    const out = parseRespString("signatures=WyJiYWRfcG9pbnQxIiwgImJhZF9wb2ludDIiXQ==");
                    const xhr = validateAndStoreTokens(newUrl, details.tabId, tokens, out);
                    xhr.onreadystatechange();
                }
                setTimeSinceLastResp(0); // reset the variables
                setMock(TOKEN_COUNT_STR, 0);
                const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                expect(run).toThrow();
                expect(updateIconMock).toBeCalledTimes(1);
                expect(updateBrowserTabMock).not.toBeCalled();
            });

            describe("DLEQ formatting errors", () => {
                test("proof is not JSON", () => {
                    function run() {
                        const tokens = [];
                        for (let i=0; i<testTokens.length; i++) {
                            tokens[i] = {data: testTokens[i].data, point: sec1DecodePointFromBytes(testTokens[i].point), blind: getBigNumFromBytes(testTokens[i].blind)};
                        }
                        const out = parseRespString(respBadJson);
                        const xhr = validateAndStoreTokens(newUrl, details.tabId, tokens, out);
                        xhr.onreadystatechange();
                    }
                    setTimeSinceLastResp(0); // reset the variables
                    setMock(TOKEN_COUNT_STR, 0);
                    const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                    expect(run).toThrow();
                    expect(updateIconMock).toBeCalledTimes(1);
                    expect(updateBrowserTabMock).not.toBeCalled();
                });

                test("proof has bad points", () => {
                    function run() {
                        const tokens = [];
                        for (let i=0; i<testTokens.length; i++) {
                            tokens[i] = {data: testTokens[i].data, point: sec1DecodePointFromBytes(testTokens[i].point), blind: getBigNumFromBytes(testTokens[i].blind)};
                        }
                        const out = parseRespString(respBadPoints);
                        const xhr = validateAndStoreTokens(newUrl, details.tabId, tokens, out);
                        xhr.onreadystatechange();
                    }
                    setTimeSinceLastResp(0); // reset the variables
                    setMock(TOKEN_COUNT_STR, 0);
                    const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                    expect(run).toThrow();
                    expect(updateIconMock).toBeCalledTimes(1);
                    expect(updateBrowserTabMock).not.toBeCalled();
                });

                test("proof should not verify (bad lengths)", () => {
                    function run() {
                        const tokens = [];
                        for (let i=0; i<testTokensBadLength.length; i++) {
                            tokens[i] = {data: testTokens[i].data, point: sec1DecodePointFromBytes(testTokens[i].point), blind: getBigNumFromBytes(testTokens[i].blind)};
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
                    setMock(TOKEN_COUNT_STR, 0);
                    const newUrl = new URL(EXAMPLE_HREF + EXAMPLE_SUFFIX);
                    expect(run).toThrowError("Unable to verify DLEQ");
                    expect(consoleNew.error).not.toHaveBeenCalledWith(workflow.__get__("DIGEST_INEQUALITY_ERR"));
                    expect(updateIconMock).toBeCalledTimes(1);
                    expect(updateBrowserTabMock).not.toBeCalled();
                });

                test("proof should not verify", () => {
                    function run() {
                        const tokens = [];
                        for (let i=0; i<testTokens.length; i++) {
                            tokens[i] = {data: testTokens[i].data, point: sec1DecodePointFromBytes(testTokens[i].point), blind: getBigNumFromBytes(testTokens[i].blind)};
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
                    setMock(TOKEN_COUNT_STR, 0);
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

function getSpentHosts(key) {
    const spentHosts = workflow.__get__("spentHosts", spentHosts);
    return spentHosts[key];
}
function setSpentHosts(key, value) {
    const spentHosts = new Map();
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
    workflow.__set__("clearCachedCommitments", clearCachedCommitmentsMock);
    workflow.__set__("updateIcon", updateIconMock);
    workflow.__set__("updateBrowserTab", updateBrowserTabMock);
    workflow.__set__("setSpendFlag", setSpendFlag);
    workflow.__set__("createShake256", createShake256);
    workflow.__set__("TOKENS_PER_REQUEST", 3);
}
function setXHR(xhr) {
    workflow.__set__("XMLHttpRequest", xhr);
}
