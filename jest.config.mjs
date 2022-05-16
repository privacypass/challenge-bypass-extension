export default {
    moduleFileExtensions: ['js'],
    transform: {},
    setupFiles: ['./jest.setup.mjs'],
    moduleNameMapper: {
        '^@root/(.*)': '<rootDir>/$1',
        '^@public/(.*)': '<rootDir>/public/$1',
        '^@popup/(.*)': '<rootDir>/src/popup/$1',
    },
    collectCoverage: true,
    verbose: true,
};
