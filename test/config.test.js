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
