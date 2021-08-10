/** @type {import('@ts-jest/dist/types').InitialOptionsTsJest} */
module.exports = {
    preset: 'ts-jest',
    setupFiles: ['./jest.setup.ts'],
    testEnvironment: 'jsdom',
    moduleNameMapper: {
        "^@root/(.*)": "<rootDir>/$1",
        "^@public/(.*)": "<rootDir>/public/$1",
        "^@background/(.*)": "<rootDir>/src/background/$1",
        "^@popup/(.*)": "<rootDir>/src/popup/$1"
    },
};
