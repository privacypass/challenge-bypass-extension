/**
* Integration tests for token generation and commitment functionality
* 
* @author: Alex Davidson
*/
import rewire from "rewire";
var workflow = rewire("../addon/compiled/test_compiled.js");
var URL = window.URL;

/**
* Functions
*/
const CreateBlindToken = workflow.__get__('CreateBlindToken');
const GenerateNewTokens = workflow.__get__('GenerateNewTokens');
let consoleMock;
let CreateBlindTokenMock;
beforeEach(() => {
    consoleMock = {
        warn: jest.fn()
    }
    workflow.__set__("console", consoleMock);
    let count = 0;
    CreateBlindTokenMock = function() {
        let token;
        if (count != 1) {
            token = CreateBlindToken();
        }
        count++;
        return token;
    }
});

/**
* Tests
*/
describe("check that null point errors are caught in token generation", () => {
    test("check that token generation happens correctly", () => {
        let tokens = GenerateNewTokens(3);
        expect(tokens.length == 3).toBeTruthy();
        let consoleNew = workflow.__get__("console");
        expect(consoleNew.warn).not.toBeCalled();
    });

    test("check that null tokens are caught and ignored", () => {
        workflow.__set__("CreateBlindToken", CreateBlindTokenMock);
        let tokens = GenerateNewTokens(3);
        expect(tokens.length == 2).toBeTruthy();
        let consoleNew = workflow.__get__("console");
        expect(consoleNew.warn).toBeCalled();
    });
});