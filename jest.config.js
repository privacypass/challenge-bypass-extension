export default {
    preset: 'ts-jest/presets/js-with-ts-esm',
    setupFiles: ['./jest.setup.ts'],
    globals: {
        'ts-jest': {
            useESM: true,
        },
    },
    transform: {},
    transformIgnorePatterns: ['.js'],
    testEnvironment: 'jsdom',
    moduleNameMapper: {
        '^@root/(.*)': '<rootDir>/$1',
        '^@public/(.*)': '<rootDir>/public/$1',
        '^@popup/(.*)': '<rootDir>/src/popup/$1',
    },
    verbose: true,
}
